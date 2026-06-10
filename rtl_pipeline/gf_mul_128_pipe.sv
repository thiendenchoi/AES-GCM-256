// =============================================================================
// gf_mul_128_pipe.sv — 2-Stage Pipelined GF(2^128) Multiplier for GHASH
// =============================================================================
// Polynomial: x^128 + x^7 + x^2 + x + 1  (R = 0xE1000...0)
//
// Stage 1 (combinational): Processes bits 127..64 of X  → pipeline register
// Stage 2 (combinational): Processes bits  63..0  of X  → output register
//
// Latency : 2 clock cycles
// Throughput: 1 result / 2 cycles  (serial GHASH dependency)
// At 156.25 MHz  →  128 bits / 2 cycles * 156.25 MHz = 10 Gbps
// =============================================================================
module gf_mul_128_pipe (
    input  logic         clk,
    input  logic         rst_n,

    input  logic [127:0] x_i,       // GHASH input block  (Y_{i-1} XOR data)
    input  logic [127:0] y_i,       // Hash subkey H
    input  logic         valid_i,   // Pulse high for 1 cycle to start

    output logic [127:0] z_o,       // Result
    output logic         valid_o    // High for 1 cycle when result ready
);

    localparam [127:0] R = 128'hE1000000000000000000000000000000;

    // =====================================================================
    // STAGE 1: Process upper 64 bits of X (bits 127..64)
    // =====================================================================
    // Compute V chain:  V[0] = Y,  V[i+1] = (V[i]>>1) ^ (V[i][0]?R:0)
    logic [127:0] s1_v [0:64];
    assign s1_v[0] = y_i;

    genvar i;
    generate
        for (i = 0; i < 64; i++) begin : gen_s1_v
            assign s1_v[i+1] = {1'b0, s1_v[i][127:1]} ^ (s1_v[i][0] ? R : 128'h0);
        end
    endgenerate

    // Accumulate partial Z for bits 127..64
    logic [127:0] s1_acc [0:64];
    assign s1_acc[0] = 128'h0;

    generate
        for (i = 0; i < 64; i++) begin : gen_s1_acc
            assign s1_acc[i+1] = s1_acc[i] ^ (x_i[127-i] ? s1_v[i] : 128'h0);
        end
    endgenerate

    // Stage 1 outputs (combinational)
    wire [127:0] s1_z_out = s1_acc[64];     // partial Z after 64 iterations
    wire [127:0] s1_v_out = s1_v[64];       // V after 64 shift-reduces
    wire  [63:0] s1_x_low = x_i[63:0];     // remaining X bits

    // =====================================================================
    // Pipeline Register (between stage 1 and stage 2)
    // =====================================================================
    logic [127:0] pr_z_q;      // partial Z
    logic [127:0] pr_v_q;      // V state
    logic  [63:0] pr_x_q;      // remaining X bits
    logic         pr_valid_q;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            pr_z_q     <= 128'h0;
            pr_v_q     <= 128'h0;
            pr_x_q     <= 64'h0;
            pr_valid_q <= 1'b0;
        end else begin
            pr_z_q     <= s1_z_out;
            pr_v_q     <= s1_v_out;
            pr_x_q     <= s1_x_low;
            pr_valid_q <= valid_i;
        end
    end

    // =====================================================================
    // STAGE 2: Process lower 64 bits of X (bits 63..0)
    // =====================================================================
    logic [127:0] s2_v [0:64];
    assign s2_v[0] = pr_v_q;

    generate
        for (i = 0; i < 64; i++) begin : gen_s2_v
            assign s2_v[i+1] = {1'b0, s2_v[i][127:1]} ^ (s2_v[i][0] ? R : 128'h0);
        end
    endgenerate

    logic [127:0] s2_acc [0:64];
    assign s2_acc[0] = pr_z_q;

    generate
        for (i = 0; i < 64; i++) begin : gen_s2_acc
            assign s2_acc[i+1] = s2_acc[i] ^ (pr_x_q[63-i] ? s2_v[i] : 128'h0);
        end
    endgenerate

    // =====================================================================
    // Output Register
    // =====================================================================
    logic [127:0] out_z_q;
    logic         out_valid_q;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            out_z_q     <= 128'h0;
            out_valid_q <= 1'b0;
        end else begin
            out_z_q     <= s2_acc[64];
            out_valid_q <= pr_valid_q;
        end
    end

    assign z_o     = out_z_q;
    assign valid_o = out_valid_q;

endmodule
