module aes_256_core (
    input  logic         clk,
    input  logic         rst_n,

    // Key control
    input  logic         load_key_i,
    input  logic [255:0] key_i,
    output logic         key_ready_o,

    // Data control
    input  logic         start_i,
    output logic         ready_o,
    output logic         done_o,
    input  logic [127:0] data_i,
    output logic [127:0] data_o
);

    // Key Expansion Instance
    logic [14:0][127:0] round_keys;
    logic key_expand_start;
    logic key_expand_ready;
    logic key_expand_done;
    logic key_ready_q, key_ready_d;

    aes_key_expand_256 key_expand_inst (
        .clk(clk),
        .rst_n(rst_n),
        .start_i(key_expand_start),
        .key_i(key_i),
        .ready_o(key_expand_ready),
        .done_o(key_expand_done),
        .round_keys_o(round_keys)
    );

    // Key ready status latch
    always @(*) begin
        key_expand_start = 1'b0;
        key_ready_d = key_ready_q;
        if (load_key_i && key_expand_ready) begin
            key_expand_start = 1'b1;
            key_ready_d = 1'b0;
        end else if (key_expand_done) begin
            key_ready_d = 1'b1;
        end
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            key_ready_q <= 1'b0;
        end else begin
            key_ready_q <= key_ready_d;
        end
    end

    assign key_ready_o = key_ready_q;

    // --- State Machine for Encryption ---
    typedef enum logic [1:0] {
        IDLE,
        ROUNDS,
        DONE
    } state_e;

    state_e state_q, state_d;
    logic [3:0] round_q, round_d;
    logic [127:0] state_reg_q, state_reg_d;

    // Helper functions for AES State Matrix mapping
    // AES state: 4x4 bytes. In big endian representation:
    // s[r][c] = data_i[127 - 8*(r + 4*c) -: 8]
    function automatic logic [7:0] get_byte(logic [127:0] st, int r, int c);
        return st[127 - 8*(r + 4*c) -: 8];
    endfunction

    function automatic logic [7:0] xtime(logic [7:0] x);
        return (x << 1) ^ (x[7] ? 8'h1b : 8'h00);
    endfunction

    // 16 Sboxes for SubBytes round
    logic [7:0] sbox_in [0:15];
    logic [7:0] sbox_out [0:15];

    genvar gi;
    generate
        for (gi = 0; gi < 16; gi++) begin : gen_sboxes
            aes_sbox sb (
                .in (sbox_in[gi]),
                .out(sbox_out[gi])
            );
        end
    endgenerate

    // SubBytes input routing: always SubBytes of current state_reg_q
    genvar gr, gc;
    generate
        for (gr = 0; gr < 4; gr++) begin : gen_sbox_in_r
            for (gc = 0; gc < 4; gc++) begin : gen_sbox_in_c
                assign sbox_in[gr + 4*gc] = get_byte(state_reg_q, gr, gc);
            end
        end
    endgenerate

    // Intermediate states
    logic [127:0] round_result;
    logic [7:0] sb_state [0:3][0:3];
    logic [7:0] sr_state [0:3][0:3];
    logic [7:0] mc_state [0:3][0:3];

    generate
        for (gr = 0; gr < 4; gr++) begin : gen_sb_state_r
            for (gc = 0; gc < 4; gc++) begin : gen_sb_state_c
                assign sb_state[gr][gc] = sbox_out[gr + 4*gc];
            end
        end
    endgenerate

    // Row 0: shift 0
    assign sr_state[0][0] = sb_state[0][0];
    assign sr_state[0][1] = sb_state[0][1];
    assign sr_state[0][2] = sb_state[0][2];
    assign sr_state[0][3] = sb_state[0][3];
    // Row 1: shift 1 left
    assign sr_state[1][0] = sb_state[1][1];
    assign sr_state[1][1] = sb_state[1][2];
    assign sr_state[1][2] = sb_state[1][3];
    assign sr_state[1][3] = sb_state[1][0];
    // Row 2: shift 2 left
    assign sr_state[2][0] = sb_state[2][2];
    assign sr_state[2][1] = sb_state[2][3];
    assign sr_state[2][2] = sb_state[2][0];
    assign sr_state[2][3] = sb_state[2][1];
    // Row 3: shift 3 left (which is 1 right)
    assign sr_state[3][0] = sb_state[3][3];
    assign sr_state[3][1] = sb_state[3][0];
    assign sr_state[3][2] = sb_state[3][1];
    assign sr_state[3][3] = sb_state[3][2];

    // MixColumns
    generate
        for (gc = 0; gc < 4; gc++) begin : gen_mc
            logic [7:0] mc_a0, mc_a1, mc_a2, mc_a3, mc_h;
            assign mc_a0 = sr_state[0][gc];
            assign mc_a1 = sr_state[1][gc];
            assign mc_a2 = sr_state[2][gc];
            assign mc_a3 = sr_state[3][gc];
            assign mc_h  = mc_a0 ^ mc_a1 ^ mc_a2 ^ mc_a3;

            assign mc_state[0][gc] = mc_a0 ^ mc_h ^ xtime(mc_a0 ^ mc_a1);
            assign mc_state[1][gc] = mc_a1 ^ mc_h ^ xtime(mc_a1 ^ mc_a2);
            assign mc_state[2][gc] = mc_a2 ^ mc_h ^ xtime(mc_a2 ^ mc_a3);
            assign mc_state[3][gc] = mc_a3 ^ mc_h ^ xtime(mc_a3 ^ mc_a0);
        end
    endgenerate

    always @(*) begin
        if (round_q == 4'd14) begin
            // Final round has no MixColumns
            for (int r = 0; r < 4; r++) begin
                for (int c = 0; c < 4; c++) begin
                    round_result[127 - 8*(r + 4*c) -: 8] = sr_state[r][c] ^ get_byte(round_keys[14], r, c);
                end
            end
        end else begin
            // Rounds 1 to 13
            for (int r = 0; r < 4; r++) begin
                for (int c = 0; c < 4; c++) begin
                    round_result[127 - 8*(r + 4*c) -: 8] = mc_state[r][c] ^ get_byte(round_keys[round_q], r, c);
                end
            end
        end
    end

    // --- State Machine ---
    always @(*) begin
        state_d     = state_q;
        round_d     = round_q;
        state_reg_d = state_reg_q;

        case (state_q)
            IDLE: begin
                if (start_i && key_ready_q) begin
                    // Round 0: AddRoundKey immediately on input data
                    state_reg_d = data_i ^ round_keys[0];
                    round_d     = 4'd1;
                    state_d     = ROUNDS;
                end
            end

            ROUNDS: begin
                state_reg_d = round_result;
                if (round_q == 4'd14) begin
                    state_d = DONE;
                end else begin
                    round_d = round_q + 4'd1;
                end
            end

            DONE: begin
                state_d = IDLE;
            end

            default: state_d = IDLE;
        endcase
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_q     <= IDLE;
            round_q     <= 4'd0;
            state_reg_q <= 128'h0;
        end else begin
            state_q     <= state_d;
            round_q     <= round_d;
            state_reg_q <= state_reg_d;
        end
    end

    assign data_o  = state_reg_q;
    assign ready_o = (state_q == IDLE) && key_ready_q;
    assign done_o  = (state_q == DONE);

endmodule
