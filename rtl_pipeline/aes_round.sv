// =============================================================================
// aes_round.sv — Combinational AES-256 Single Round
// =============================================================================
// Implements: SubBytes → ShiftRows → MixColumns (optional) → AddRoundKey
// Used as building block for fully-pipelined AES-256 core.
// =============================================================================
module aes_round (
    input  logic [127:0] state_i,
    input  logic [127:0] round_key_i,
    input  logic         is_final_i,   // 1 = Round 14: skip MixColumns
    output logic [127:0] state_o
);

    // --- Byte extraction helper ---
    // AES state matrix (column-major):
    //   s[r][c] is at bit position [127 - 8*(r + 4*c) -: 8]
    function automatic logic [7:0] get_byte(logic [127:0] st, int r, int c);
        return st[127 - 8*(r + 4*c) -: 8];
    endfunction

    function automatic logic [7:0] xtime(logic [7:0] x);
        return (x << 1) ^ (x[7] ? 8'h1b : 8'h00);
    endfunction

    // --- SubBytes: 16 parallel S-Box lookups ---
    logic [7:0] sbox_in  [0:15];
    logic [7:0] sbox_out [0:15];

    genvar gi;
    generate
        for (gi = 0; gi < 16; gi++) begin : gen_sbox
            aes_sbox sb (.in(sbox_in[gi]), .out(sbox_out[gi]));
        end
    endgenerate

    // Route state bytes to S-Box inputs
    genvar gr, gc;
    generate
        for (gr = 0; gr < 4; gr++) begin : gen_sbin_r
            for (gc = 0; gc < 4; gc++) begin : gen_sbin_c
                assign sbox_in[gr + 4*gc] = get_byte(state_i, gr, gc);
            end
        end
    endgenerate

    // SubBytes output as 2D array
    logic [7:0] sb [0:3][0:3];
    generate
        for (gr = 0; gr < 4; gr++) begin : gen_sb_r
            for (gc = 0; gc < 4; gc++) begin : gen_sb_c
                assign sb[gr][gc] = sbox_out[gr + 4*gc];
            end
        end
    endgenerate

    // --- ShiftRows ---
    logic [7:0] sr [0:3][0:3];
    // Row 0: no shift
    assign sr[0][0] = sb[0][0]; assign sr[0][1] = sb[0][1];
    assign sr[0][2] = sb[0][2]; assign sr[0][3] = sb[0][3];
    // Row 1: shift left 1
    assign sr[1][0] = sb[1][1]; assign sr[1][1] = sb[1][2];
    assign sr[1][2] = sb[1][3]; assign sr[1][3] = sb[1][0];
    // Row 2: shift left 2
    assign sr[2][0] = sb[2][2]; assign sr[2][1] = sb[2][3];
    assign sr[2][2] = sb[2][0]; assign sr[2][3] = sb[2][1];
    // Row 3: shift left 3
    assign sr[3][0] = sb[3][3]; assign sr[3][1] = sb[3][0];
    assign sr[3][2] = sb[3][1]; assign sr[3][3] = sb[3][2];

    // --- MixColumns ---
    logic [7:0] mc [0:3][0:3];
    generate
        for (gc = 0; gc < 4; gc++) begin : gen_mc
            logic [7:0] a0, a1, a2, a3, h;
            assign a0 = sr[0][gc];
            assign a1 = sr[1][gc];
            assign a2 = sr[2][gc];
            assign a3 = sr[3][gc];
            assign h  = a0 ^ a1 ^ a2 ^ a3;
            assign mc[0][gc] = a0 ^ h ^ xtime(a0 ^ a1);
            assign mc[1][gc] = a1 ^ h ^ xtime(a1 ^ a2);
            assign mc[2][gc] = a2 ^ h ^ xtime(a2 ^ a3);
            assign mc[3][gc] = a3 ^ h ^ xtime(a3 ^ a0);
        end
    endgenerate

    // --- Output: Select MC or SR (final round) then AddRoundKey ---
    always @(*) begin
        for (int r = 0; r < 4; r++) begin
            for (int c = 0; c < 4; c++) begin
                if (is_final_i)
                    state_o[127 - 8*(r+4*c) -: 8] = sr[r][c] ^ round_key_i[127 - 8*(r+4*c) -: 8];
                else
                    state_o[127 - 8*(r+4*c) -: 8] = mc[r][c] ^ round_key_i[127 - 8*(r+4*c) -: 8];
            end
        end
    end

endmodule
