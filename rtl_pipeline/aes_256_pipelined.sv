// =============================================================================
// aes_256_pipelined.sv — Fully Pipelined AES-256 Encryption Core
// =============================================================================
// Architecture (from user's pipeline diagram):
//   15 pipeline stages (Reg0 .. Reg14)
//   Stage 0 : AddRoundKey(RK0) only
//   Stages 1-13 : SubBytes → ShiftRows → MixColumns → AddRoundKey(RK_i)
//   Stage 14 : SubBytes → ShiftRows → AddRoundKey(RK14) [no MixColumns]
//
// Each pipeline register holds:
//   { state[127:0], valid, keep[15:0], last }
//
// Throughput : 1 block / clock cycle  (after pipeline is full)
// Latency   : 15 clock cycles
// =============================================================================
module aes_256_pipelined (
    input  logic         clk,
    input  logic         rst_n,
    input  logic         en_i,        // Pipeline enable (1=advance, 0=stall)

    // --- Key loading ---
    input  logic         load_key_i,
    input  logic [255:0] key_i,
    output logic         key_ready_o,

    // --- Pipeline input ---
    input  logic [127:0] data_i,
    input  logic         valid_i,
    input  logic [15:0]  keep_i,
    input  logic         last_i,

    // --- Pipeline output (15 cycles after input) ---
    output logic [127:0] data_o,
    output logic         valid_o,
    output logic [15:0]  keep_o,
    output logic         last_o
);

    // =================================================================
    // Key Expansion (reuses existing sequential module)
    // =================================================================
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

    // Key ready latch
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
        if (!rst_n)
            key_ready_q <= 1'b0;
        else
            key_ready_q <= key_ready_d;
    end

    assign key_ready_o = key_ready_q;

    // =================================================================
    // Pipeline Registers:  stage_state[0..14], stage_valid, stage_keep, stage_last
    // =================================================================
    logic [127:0] stage_state [0:14];
    logic         stage_valid [0:14];
    logic [15:0]  stage_keep  [0:14];
    logic         stage_last  [0:14];

    // =================================================================
    // Combinational Round Logic
    // =================================================================
    // round_out[0] = data_i XOR round_keys[0]  (initial AddRoundKey)
    logic [127:0] round_out_0;
    assign round_out_0 = data_i ^ round_keys[0];

    // round_out[1..13] = full AES rounds (SubBytes+ShiftRows+MixColumns+AddRoundKey)
    logic [127:0] round_out [1:14];

    genvar ri;
    generate
        for (ri = 1; ri <= 13; ri++) begin : gen_round
            aes_round round_inst (
                .state_i    (stage_state[ri-1]),
                .round_key_i(round_keys[ri]),
                .is_final_i (1'b0),
                .state_o    (round_out[ri])
            );
        end
    endgenerate

    // round_out[14] = final round (no MixColumns)
    aes_round round_14 (
        .state_i    (stage_state[13]),
        .round_key_i(round_keys[14]),
        .is_final_i (1'b1),
        .state_o    (round_out[14])
    );

    // =================================================================
    // Pipeline Register Update
    // =================================================================
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            stage_state[0] <= 128'h0; stage_valid[0] <= 1'b0; stage_keep[0] <= 16'h0; stage_last[0] <= 1'b0;
            stage_state[1] <= 128'h0; stage_valid[1] <= 1'b0; stage_keep[1] <= 16'h0; stage_last[1] <= 1'b0;
            stage_state[2] <= 128'h0; stage_valid[2] <= 1'b0; stage_keep[2] <= 16'h0; stage_last[2] <= 1'b0;
            stage_state[3] <= 128'h0; stage_valid[3] <= 1'b0; stage_keep[3] <= 16'h0; stage_last[3] <= 1'b0;
            stage_state[4] <= 128'h0; stage_valid[4] <= 1'b0; stage_keep[4] <= 16'h0; stage_last[4] <= 1'b0;
            stage_state[5] <= 128'h0; stage_valid[5] <= 1'b0; stage_keep[5] <= 16'h0; stage_last[5] <= 1'b0;
            stage_state[6] <= 128'h0; stage_valid[6] <= 1'b0; stage_keep[6] <= 16'h0; stage_last[6] <= 1'b0;
            stage_state[7] <= 128'h0; stage_valid[7] <= 1'b0; stage_keep[7] <= 16'h0; stage_last[7] <= 1'b0;
            stage_state[8] <= 128'h0; stage_valid[8] <= 1'b0; stage_keep[8] <= 16'h0; stage_last[8] <= 1'b0;
            stage_state[9] <= 128'h0; stage_valid[9] <= 1'b0; stage_keep[9] <= 16'h0; stage_last[9] <= 1'b0;
            stage_state[10] <= 128'h0; stage_valid[10] <= 1'b0; stage_keep[10] <= 16'h0; stage_last[10] <= 1'b0;
            stage_state[11] <= 128'h0; stage_valid[11] <= 1'b0; stage_keep[11] <= 16'h0; stage_last[11] <= 1'b0;
            stage_state[12] <= 128'h0; stage_valid[12] <= 1'b0; stage_keep[12] <= 16'h0; stage_last[12] <= 1'b0;
            stage_state[13] <= 128'h0; stage_valid[13] <= 1'b0; stage_keep[13] <= 16'h0; stage_last[13] <= 1'b0;
            stage_state[14] <= 128'h0; stage_valid[14] <= 1'b0; stage_keep[14] <= 16'h0; stage_last[14] <= 1'b0;
        end else if (en_i) begin
            // Stage 0: initial AddRoundKey
            stage_state[0] <= round_out_0;
            stage_valid[0] <= valid_i;
            stage_keep[0]  <= keep_i;
            stage_last[0]  <= last_i;

            // Stages 1-14: round logic output
            stage_state[1] <= round_out[1];   stage_valid[1] <= stage_valid[0];   stage_keep[1] <= stage_keep[0];   stage_last[1] <= stage_last[0];
            stage_state[2] <= round_out[2];   stage_valid[2] <= stage_valid[1];   stage_keep[2] <= stage_keep[1];   stage_last[2] <= stage_last[1];
            stage_state[3] <= round_out[3];   stage_valid[3] <= stage_valid[2];   stage_keep[3] <= stage_keep[2];   stage_last[3] <= stage_last[2];
            stage_state[4] <= round_out[4];   stage_valid[4] <= stage_valid[3];   stage_keep[4] <= stage_keep[3];   stage_last[4] <= stage_last[3];
            stage_state[5] <= round_out[5];   stage_valid[5] <= stage_valid[4];   stage_keep[5] <= stage_keep[4];   stage_last[5] <= stage_last[4];
            stage_state[6] <= round_out[6];   stage_valid[6] <= stage_valid[5];   stage_keep[6] <= stage_keep[5];   stage_last[6] <= stage_last[5];
            stage_state[7] <= round_out[7];   stage_valid[7] <= stage_valid[6];   stage_keep[7] <= stage_keep[6];   stage_last[7] <= stage_last[6];
            stage_state[8] <= round_out[8];   stage_valid[8] <= stage_valid[7];   stage_keep[8] <= stage_keep[7];   stage_last[8] <= stage_last[7];
            stage_state[9] <= round_out[9];   stage_valid[9] <= stage_valid[8];   stage_keep[9] <= stage_keep[8];   stage_last[9] <= stage_last[8];
            stage_state[10] <= round_out[10]; stage_valid[10] <= stage_valid[9];  stage_keep[10] <= stage_keep[9];  stage_last[10] <= stage_last[9];
            stage_state[11] <= round_out[11]; stage_valid[11] <= stage_valid[10]; stage_keep[11] <= stage_keep[10]; stage_last[11] <= stage_last[10];
            stage_state[12] <= round_out[12]; stage_valid[12] <= stage_valid[11]; stage_keep[12] <= stage_keep[11]; stage_last[12] <= stage_last[11];
            stage_state[13] <= round_out[13]; stage_valid[13] <= stage_valid[12]; stage_keep[13] <= stage_keep[12]; stage_last[13] <= stage_last[12];
            stage_state[14] <= round_out[14]; stage_valid[14] <= stage_valid[13]; stage_keep[14] <= stage_keep[13]; stage_last[14] <= stage_last[13];
        end
    end

    // =================================================================
    // Outputs
    // =================================================================
    always_comb begin
        data_o  = stage_state[14];
        valid_o = stage_valid[14];
        keep_o  = stage_keep[14];
        last_o  = stage_last[14];
    end

endmodule
