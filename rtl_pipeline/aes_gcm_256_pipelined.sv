// =============================================================================
// aes_gcm_256_pipelined.sv — AES-GCM-256 with Pipelined AES + Pipelined GHASH
// =============================================================================
// Uses:
//   - aes_256_pipelined : 15-stage pipelined AES (1 block/cycle throughput)
//   - gf_mul_128_pipe   : 2-stage pipelined GHASH (2 cycles latency)
//
// Same external interface as original aes_gcm_256_encrypt for compatibility.
// =============================================================================
module aes_gcm_256_pipelined (
    input  logic         clk,
    input  logic         rst_n,

    // Control
    input  logic         start_i,
    output logic         ready_o,
    output logic         done_o,

    // Key & IV
    input  logic [255:0] key_i,
    input  logic [95:0]  iv_i,
    input  logic [63:0]  aad_len_i,
    input  logic [63:0]  pt_len_i,

    // Input data stream (AAD first, then PT)
    input  logic [127:0] data_i,
    input  logic         data_val_i,
    output logic         data_ready_o,

    // Output data stream (Ciphertext)
    output logic [127:0] data_o,
    output logic         data_val_o,

    // Tag
    output logic [127:0] tag_o
);

    // --- State Definitions ---
    typedef enum logic [3:0] {
        IDLE,
        LOAD_KEY,
        CALC_H,
        AAD_INPUT,
        AAD_HASH,
        PT_PIPE,
        CALC_L,
        CALC_TAG_ENC,
        CALC_TAG_DONE
    } state_e;

    state_e state_q, state_d;

    // --- Registers ---
    logic [255:0] key_q, key_d;
    logic [95:0]  iv_q, iv_d;
    logic [63:0]  aad_len_q, aad_len_d;
    logic [63:0]  pt_len_q, pt_len_d;

    logic [63:0]  aad_blocks_q, aad_blocks_d;
    logic [63:0]  pt_blocks_q, pt_blocks_d;
    logic [63:0]  blk_cnt_q, blk_cnt_d;

    logic [127:0] H_q, H_d;
    logic [127:0] J0_q, J0_d;
    logic [127:0] Y_q, Y_d;
    logic [127:0] ctr_q, ctr_d;
    logic [127:0] keystream_q, keystream_d;
    logic [127:0] din_reg_q, din_reg_d;
    logic [127:0] EJ0_q, EJ0_d;
    logic [127:0] ct_full;

    // Fully pipelined GCM control counters
    logic [63:0]  aes_in_cnt_q, aes_in_cnt_d;
    logic [63:0]  aes_out_cnt_q, aes_out_cnt_d;
    logic [63:0]  ghash_in_cnt_q, ghash_in_cnt_d;
    logic [63:0]  ghash_out_cnt_q, ghash_out_cnt_d;
    logic         send_phase_q, send_phase_d;
    logic         stall_aes;

    // Flag to track if AES pipeline input has been sent
    logic         aes_sent_q, aes_sent_d;
    // Flag to track if GHASH pipeline input has been sent
    logic         ghash_sent_q, ghash_sent_d;

    // --- AES Pipelined Core ---
    logic         aes_en;
    logic         aes_load_key;
    logic         aes_key_ready;
    logic [127:0] aes_data_in;
    logic         aes_valid_in;
    logic [127:0] aes_data_out;
    logic         aes_valid_out;

    aes_256_pipelined aes_pipe_inst (
        .clk(clk),
        .rst_n(rst_n),
        .en_i(aes_en),
        .load_key_i(aes_load_key),
        .key_i(key_q),
        .key_ready_o(aes_key_ready),
        .data_i(aes_data_in),
        .valid_i(aes_valid_in),
        .keep_i(16'hFFFF),
        .last_i(1'b0),
        .data_o(aes_data_out),
        .valid_o(aes_valid_out),
        .keep_o(),
        .last_o()
    );

    // --- GHASH Pipelined Multiplier ---
    logic [127:0] ghash_x;
    logic [127:0] ghash_y;
    logic         ghash_valid_in;
    logic [127:0] ghash_z;
    logic         ghash_valid_out;

    gf_mul_128_pipe ghash_inst (
        .clk(clk),
        .rst_n(rst_n),
        .x_i(ghash_x),
        .y_i(ghash_y),
        .valid_i(ghash_valid_in),
        .z_o(ghash_z),
        .valid_o(ghash_valid_out)
    );

    // --- Padding function ---
    function automatic logic [127:0] pad_block(logic [127:0] val, logic [3:0] num_bytes);
        logic [127:0] padded;
        padded = val;
        if (num_bytes != 4'd0) begin
            for (int i = 0; i < 16; i++) begin
                if (i >= num_bytes) begin
                    padded[127 - 8*i -: 8] = 8'h00;
                end
            end
        end
        return padded;
    endfunction

    // --- FSM Combinational Logic ---
    always @(*) begin
        ct_full        = 128'h0;
        state_d        = state_q;
        key_d          = key_q;
        iv_d           = iv_q;
        aad_len_d      = aad_len_q;
        pt_len_d       = pt_len_q;
        aad_blocks_d   = aad_blocks_q;
        pt_blocks_d    = pt_blocks_q;
        blk_cnt_d      = blk_cnt_q;
        H_d            = H_q;
        J0_d           = J0_q;
        Y_d            = Y_q;
        ctr_d          = ctr_q;
        keystream_d    = keystream_q;
        din_reg_d      = din_reg_q;
        EJ0_d          = EJ0_q;
        aes_sent_d     = aes_sent_q;
        ghash_sent_d   = ghash_sent_q;

        // Counter defaults
        aes_in_cnt_d    = aes_in_cnt_q;
        aes_out_cnt_d   = aes_out_cnt_q;
        ghash_in_cnt_d  = ghash_in_cnt_q;
        ghash_out_cnt_d = ghash_out_cnt_q;
        send_phase_d    = send_phase_q;
        stall_aes       = 1'b0;

        // Default outputs
        ready_o        = 1'b0;
        done_o         = 1'b0;
        data_ready_o   = 1'b0;
        data_o         = 128'h0;
        data_val_o     = 1'b0;

        // AES pipeline defaults
        aes_load_key   = 1'b0;
        aes_data_in    = 128'h0;
        aes_valid_in   = 1'b0;

        // GHASH pipeline defaults
        ghash_x        = 128'h0;
        ghash_y        = 128'h0;
        ghash_valid_in = 1'b0;

        case (state_q)
            // ==========================================================
            IDLE: begin
                ready_o = 1'b1;
                if (start_i) begin
                    key_d        = key_i;
                    iv_d         = iv_i;
                    aad_len_d    = aad_len_i;
                    pt_len_d     = pt_len_i;
                    aad_blocks_d = (aad_len_i == 64'd0) ? 64'd0 : (aad_len_i + 64'd15) >> 4;
                    pt_blocks_d  = (pt_len_i == 64'd0)  ? 64'd0 : (pt_len_i + 64'd15) >> 4;
                    aes_sent_d   = 1'b0;
                    ghash_sent_d = 1'b0;
                    
                    // Reset pipeline counters
                    aes_in_cnt_d    = 64'd0;
                    aes_out_cnt_d   = 64'd0;
                    ghash_in_cnt_d  = 64'd0;
                    ghash_out_cnt_d = 64'd0;
                    send_phase_d    = 1'b0;
                    
                    state_d      = LOAD_KEY;
                end
            end

            // ==========================================================
            LOAD_KEY: begin
                aes_load_key = !aes_key_ready;
                if (aes_key_ready) begin
                    aes_sent_d = 1'b0;
                    state_d    = CALC_H;
                end
            end

            // ==========================================================
            // Send 0^128 into AES pipeline, wait 15 cycles for H
            CALC_H: begin
                if (!aes_sent_q) begin
                    aes_data_in  = 128'h0;
                    aes_valid_in = 1'b1;
                    aes_sent_d   = 1'b1;
                end
                if (aes_valid_out) begin
                    H_d        = aes_data_out;
                    J0_d       = {iv_q, 32'd1};
                    Y_d        = 128'h0;
                    aes_sent_d = 1'b0;
                    if (aad_blocks_q > 64'd0) begin
                        blk_cnt_d = 64'd0;
                        state_d   = AAD_INPUT;
                    end else if (pt_blocks_q > 64'd0) begin
                        state_d   = PT_PIPE;
                    end else begin
                        state_d   = CALC_L;
                    end
                end
            end

            // ==========================================================
            AAD_INPUT: begin
                data_ready_o = 1'b1;
                if (data_val_i) begin
                    if ((blk_cnt_q == aad_blocks_q - 64'd1) && (aad_len_q[3:0] != 4'd0))
                        din_reg_d = pad_block(data_i, aad_len_q[3:0]);
                    else
                        din_reg_d = data_i;
                    ghash_sent_d = 1'b0;
                    state_d = AAD_HASH;
                end
            end

            // ==========================================================
            // GHASH AAD block (2-cycle pipelined multiply)
            AAD_HASH: begin
                if (!ghash_sent_q) begin
                    ghash_x        = Y_q ^ din_reg_q;
                    ghash_y        = H_q;
                    ghash_valid_in = 1'b1;
                    ghash_sent_d   = 1'b1;
                end
                if (ghash_valid_out) begin
                    Y_d          = ghash_z;
                    ghash_sent_d = 1'b0;
                    if (blk_cnt_q == aad_blocks_q - 64'd1) begin
                        if (pt_blocks_q > 64'd0) begin
                            state_d   = PT_PIPE;
                        end else begin
                            state_d   = CALC_L;
                        end
                    end else begin
                        blk_cnt_d = blk_cnt_q + 64'd1;
                        state_d   = AAD_INPUT;
                    end
                end
            end

            // ==========================================================
            // Fully Pipelined AES + GHASH Payload Processing
            // Runs AES counter encryption, plaintext XOR and GHASH multiply in parallel.
            PT_PIPE: begin
                stall_aes = aes_valid_out && !data_val_i;

                // 1. AES Input Counter Stream (feed counter every 2 cycles to match GHASH throughput)
                if (aes_in_cnt_q < pt_blocks_q && !stall_aes) begin
                    if (send_phase_q == 1'b0) begin
                        // J0 is IV || 32'd1, so CTR blocks start at J0+1 (i.e. IV || 32'd2)
                        aes_data_in  = {iv_q, 32'd2 + aes_in_cnt_q[31:0]};
                        aes_valid_in = 1'b1;
                        aes_in_cnt_d = aes_in_cnt_q + 64'd1;
                    end
                    send_phase_d = ~send_phase_q;
                end

                // 2. AES Output Keystream Processing & GHASH Input Handshake
                if (aes_valid_out) begin
                    data_ready_o = 1'b1;
                    if (data_val_i) begin
                        ct_full = aes_data_out ^ data_i;
                        data_val_o = 1'b1;
                        if ((aes_out_cnt_q == pt_blocks_q - 64'd1) && (pt_len_q[3:0] != 4'd0)) begin
                            data_o    = pad_block(ct_full, pt_len_q[3:0]);
                            din_reg_d = pad_block(ct_full, pt_len_q[3:0]);
                        end else begin
                            data_o    = ct_full;
                            din_reg_d = ct_full;
                        end

                        // Launch GHASH multiplication immediately
                        ghash_x        = Y_q ^ din_reg_d;
                        ghash_y        = H_q;
                        ghash_valid_in = 1'b1;
                        ghash_in_cnt_d = ghash_in_cnt_q + 64'd1;

                        aes_out_cnt_d  = aes_out_cnt_q + 64'd1;
                    end
                end

                // 3. GHASH Output Accumulator (can complete during AES stalls)
                if (ghash_valid_out) begin
                    Y_d             = ghash_z;
                    ghash_out_cnt_d = ghash_out_cnt_q + 64'd1;
                end

                // 4. Transition Condition
                if (ghash_out_cnt_q == pt_blocks_q) begin
                    state_d    = CALC_L;
                    aes_sent_d = 1'b0;
                end
            end

            // ==========================================================
            // GHASH length block (2-cycle pipelined multiply)
            CALC_L: begin
                if (!ghash_sent_q) begin
                    ghash_x        = Y_q ^ {aad_len_q[60:0], 3'b0, pt_len_q[60:0], 3'b0};
                    ghash_y        = H_q;
                    ghash_valid_in = 1'b1;
                    ghash_sent_d   = 1'b1;
                end
                if (ghash_valid_out) begin
                    Y_d          = ghash_z;
                    ghash_sent_d = 1'b0;
                    aes_sent_d   = 1'b0;
                    state_d      = CALC_TAG_ENC;
                end
            end

            // ==========================================================
            // Encrypt J0 to get EJ0 (15-cycle AES pipeline)
            CALC_TAG_ENC: begin
                if (!aes_sent_q) begin
                    aes_data_in  = J0_q;
                    aes_valid_in = 1'b1;
                    aes_sent_d   = 1'b1;
                end
                if (aes_valid_out) begin
                    EJ0_d      = aes_data_out;
                    aes_sent_d = 1'b0;
                    state_d    = CALC_TAG_DONE;
                end
            end

            // ==========================================================
            CALC_TAG_DONE: begin
                done_o  = 1'b1;
                state_d = IDLE;
            end

            default: state_d = IDLE;
        endcase
    end

    // --- Sequential logic ---
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_q      <= IDLE;
            key_q        <= 256'h0;
            iv_q         <= 96'h0;
            aad_len_q    <= 64'h0;
            pt_len_q     <= 64'h0;
            aad_blocks_q <= 64'h0;
            pt_blocks_q  <= 64'h0;
            blk_cnt_q    <= 64'h0;
            H_q          <= 128'h0;
            J0_q         <= 128'h0;
            Y_q          <= 128'h0;
            ctr_q        <= 128'h0;
            keystream_q  <= 128'h0;
            din_reg_q    <= 128'h0;
            EJ0_q        <= 128'h0;
            aes_sent_q   <= 1'b0;
            ghash_sent_q <= 1'b0;
            aes_in_cnt_q    <= 64'h0;
            aes_out_cnt_q   <= 64'h0;
            ghash_in_cnt_q  <= 64'h0;
            ghash_out_cnt_q <= 64'h0;
            send_phase_q    <= 1'b0;
        end else begin
            state_q      <= state_d;
            key_q        <= key_d;
            iv_q         <= iv_d;
            aad_len_q    <= aad_len_d;
            pt_len_q     <= pt_len_d;
            aad_blocks_q <= aad_blocks_d;
            pt_blocks_q  <= pt_blocks_d;
            blk_cnt_q    <= blk_cnt_d;
            H_q          <= H_d;
            J0_q         <= J0_d;
            Y_q          <= Y_d;
            ctr_q        <= ctr_d;
            keystream_q  <= keystream_d;
            din_reg_q    <= din_reg_d;
            EJ0_q        <= EJ0_d;
            aes_sent_q   <= aes_sent_d;
            ghash_sent_q <= ghash_sent_d;
            aes_in_cnt_q    <= aes_in_cnt_d;
            aes_out_cnt_q   <= aes_out_cnt_d;
            ghash_in_cnt_q  <= ghash_in_cnt_d;
            ghash_out_cnt_q <= ghash_out_cnt_d;
            send_phase_q    <= send_phase_d;
        end
    end

    // --- Tag output ---
    assign tag_o = Y_q ^ EJ0_q;
    assign aes_en = !stall_aes;

endmodule
