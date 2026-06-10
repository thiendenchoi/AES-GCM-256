module aes_gcm_256_encrypt (
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
        PT_CTR_INC,
        PT_CTR_ENC,
        PT_WAIT_DATA,
        PT_HASH,
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

    // --- Sub-module signals ---
    // AES Core
    logic         aes_load_key;
    logic         aes_start;
    logic [127:0] aes_data_in;
    logic         aes_key_ready;
    logic         aes_ready;
    logic         aes_done;
    logic [127:0] aes_data_out;

    aes_256_core aes_core_inst (
        .clk(clk),
        .rst_n(rst_n),
        .load_key_i(aes_load_key),
        .key_i(key_q),
        .key_ready_o(aes_key_ready),
        .start_i(aes_start),
        .ready_o(aes_ready),
        .done_o(aes_done),
        .data_i(aes_data_in),
        .data_o(aes_data_out)
    );

    // GF Multiplier
    logic         gf_start;
    logic [127:0] gf_x;
    logic [127:0] gf_y;
    logic         gf_ready;
    logic         gf_done;
    logic [127:0] gf_z;

    gf_mul_128 gf_mul_inst (
        .clk(clk),
        .rst_n(rst_n),
        .start_i(gf_start),
        .x_i(gf_x),
        .y_i(gf_y),
        .ready_o(gf_ready),
        .done_o(gf_done),
        .z_o(gf_z)
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
        ct_full      = 128'h0;
        state_d      = state_q;
        key_d        = key_q;
        iv_d         = iv_q;
        aad_len_d    = aad_len_q;
        pt_len_d     = pt_len_q;
        aad_blocks_d = aad_blocks_q;
        pt_blocks_d  = pt_blocks_q;
        blk_cnt_d    = blk_cnt_q;
        H_d          = H_q;
        J0_d         = J0_q;
        Y_d          = Y_q;
        ctr_d        = ctr_q;
        keystream_d  = keystream_q;
        din_reg_d    = din_reg_q;
        EJ0_d        = EJ0_q;

        // Default outputs
        ready_o      = 1'b0;
        done_o       = 1'b0;
        data_ready_o = 1'b0;
        data_o       = 128'h0;
        data_val_o   = 1'b0;

        // Sub-module defaults
        aes_load_key = 1'b0;
        aes_start    = 1'b0;
        aes_data_in  = 128'h0;
        gf_start     = 1'b0;
        gf_x         = 128'h0;
        gf_y         = 128'h0;

        case (state_q)
            IDLE: begin
                ready_o = 1'b1;
                if (start_i) begin
                    key_d        = key_i;
                    iv_d         = iv_i;
                    aad_len_d    = aad_len_i;
                    pt_len_d     = pt_len_i;

                    // Calculate block counts
                    aad_blocks_d = (aad_len_i == 64'd0) ? 64'd0 : (aad_len_i + 64'd15) >> 4;
                    pt_blocks_d  = (pt_len_i == 64'd0)  ? 64'd0 : (pt_len_i + 64'd15) >> 4;

                    state_d      = LOAD_KEY;
                end
            end

            LOAD_KEY: begin
                aes_load_key = !aes_key_ready;
                if (aes_key_ready) begin
                    state_d = CALC_H;
                end
            end

            CALC_H: begin
                // Encrypt 128'h0 to derive H
                aes_data_in = 128'h0;
                if (aes_ready) begin
                    aes_start = 1'b1;
                end
                if (aes_done) begin
                    H_d     = aes_data_out;
                    // J0 = IV || 32'd1
                    J0_d    = {iv_q, 32'd1};
                    Y_d     = 128'h0;
                    if (aad_blocks_q > 64'd0) begin
                        blk_cnt_d = 64'd0;
                        state_d   = AAD_INPUT;
                    end else if (pt_blocks_q > 64'd0) begin
                        blk_cnt_d = 64'd0;
                        ctr_d     = {iv_q, 32'd1};
                        state_d   = PT_CTR_INC;
                    end else begin
                        state_d   = CALC_L;
                    end
                end
            end

            AAD_INPUT: begin
                data_ready_o = 1'b1;
                if (data_val_i) begin
                    // Zero pad if it's the last block
                    if ((blk_cnt_q == aad_blocks_q - 64'd1) && (aad_len_q[3:0] != 4'd0)) begin
                        din_reg_d = pad_block(data_i, aad_len_q[3:0]);
                    end else begin
                        din_reg_d = data_i;
                    end
                    state_d = AAD_HASH;
                end
            end

            AAD_HASH: begin
                gf_x = Y_q ^ din_reg_q;
                gf_y = H_q;
                if (gf_ready) begin
                    gf_start = 1'b1;
                end
                if (gf_done) begin
                    Y_d = gf_z;
                    if (blk_cnt_q == aad_blocks_q - 64'd1) begin
                        if (pt_blocks_q > 64'd0) begin
                            blk_cnt_d = 64'd0;
                            ctr_d     = J0_q; // Start counter at J0
                            state_d   = PT_CTR_INC;
                        end else begin
                            state_d   = CALC_L;
                        end
                    end else begin
                        blk_cnt_d = blk_cnt_q + 64'd1;
                        state_d   = AAD_INPUT;
                    end
                end
            end

            PT_CTR_INC: begin
                // Increment bottom 32-bit counter
                ctr_d = {ctr_q[127:32], ctr_q[31:0] + 32'd1};
                state_d = PT_CTR_ENC;
            end

            PT_CTR_ENC: begin
                aes_data_in = ctr_q;
                if (aes_ready) begin
                    aes_start = 1'b1;
                end
                if (aes_done) begin
                    keystream_d = aes_data_out;
                    state_d     = PT_WAIT_DATA;
                end
            end

            PT_WAIT_DATA: begin
                data_ready_o = 1'b1;
                if (data_val_i) begin
                    ct_full = keystream_q ^ data_i;

                    // Output CT block
                    data_val_o = 1'b1;
                    if ((blk_cnt_q == pt_blocks_q - 64'd1) && (pt_len_q[3:0] != 4'd0)) begin
                        data_o    = pad_block(ct_full, pt_len_q[3:0]);
                        din_reg_d = pad_block(ct_full, pt_len_q[3:0]); // GHASH gets padded CT
                    end else begin
                        data_o    = ct_full;
                        din_reg_d = ct_full;
                    end
                    state_d = PT_HASH;
                end
            end

            PT_HASH: begin
                gf_x = Y_q ^ din_reg_q;
                gf_y = H_q;
                if (gf_ready) begin
                    gf_start = 1'b1;
                end
                if (gf_done) begin
                    Y_d = gf_z;
                    if (blk_cnt_q == pt_blocks_q - 64'd1) begin
                        state_d = CALC_L;
                    end else begin
                        blk_cnt_d = blk_cnt_q + 64'd1;
                        state_d   = PT_CTR_INC;
                    end
                end
            end

            CALC_L: begin
                // L = bitlen(AAD) || bitlen(PT)
                // Y_q ^ {aad_len_q[60:0], 3'b0, pt_len_q[60:0], 3'b0}
                gf_x = Y_q ^ {aad_len_q[60:0], 3'b0, pt_len_q[60:0], 3'b0};
                gf_y = H_q;
                if (gf_ready) begin
                    gf_start = 1'b1;
                end
                if (gf_done) begin
                    Y_d     = gf_z;
                    state_d = CALC_TAG_ENC;
                end
            end

            CALC_TAG_ENC: begin
                // Encrypt J0
                aes_data_in = J0_q;
                if (aes_ready) begin
                    aes_start = 1'b1;
                end
                if (aes_done) begin
                    EJ0_d   = aes_data_out;
                    state_d = CALC_TAG_DONE;
                end
            end

            CALC_TAG_DONE: begin
                done_o  = 1'b1;
                state_d = IDLE;
            end

            default: state_d = IDLE;
        endcase
    end


    // Sequential logic
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
        end
    end

    // Outputs
    assign tag_o = Y_q ^ EJ0_q;

endmodule
