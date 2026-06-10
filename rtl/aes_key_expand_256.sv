module aes_key_expand_256 (
    input  logic         clk,
    input  logic         rst_n,
    input  logic         start_i,
    input  logic [255:0] key_i,
    output logic         ready_o,
    output logic         done_o,
    output logic [14:0][127:0] round_keys_o
);

    typedef enum logic [1:0] {
        IDLE,
        EXPAND,
        DONE
    } state_e;

    state_e state_q, state_d;
    logic [3:0] step_q, step_d;
    logic [31:0] w_q [0:59];
    logic [31:0] w_d [0:59];

    // SubWord Sboxes
    logic [31:0] subword_in;
    logic [31:0] subword_out;

    aes_sbox sbox0 (.in(subword_in[31:24]), .out(subword_out[31:24]));
    aes_sbox sbox1 (.in(subword_in[23:16]), .out(subword_out[23:16]));
    aes_sbox sbox2 (.in(subword_in[15:8]),  .out(subword_out[15:8]));
    aes_sbox sbox3 (.in(subword_in[7:0]),   .out(subword_out[7:0]));

    // SubWord routing using static selection
    always @(*) begin
        case (step_q)
            4'd0:  subword_in = {w_q[7][23:0],  w_q[7][31:24]};
            4'd1:  subword_in = w_q[11];
            4'd2:  subword_in = {w_q[15][23:0], w_q[15][31:24]};
            4'd3:  subword_in = w_q[19];
            4'd4:  subword_in = {w_q[23][23:0], w_q[23][31:24]};
            4'd5:  subword_in = w_q[27];
            4'd6:  subword_in = {w_q[31][23:0], w_q[31][31:24]};
            4'd7:  subword_in = w_q[35];
            4'd8:  subword_in = {w_q[39][23:0], w_q[39][31:24]};
            4'd9:  subword_in = w_q[43];
            4'd10: subword_in = {w_q[47][23:0], w_q[47][31:24]};
            4'd11: subword_in = w_q[51];
            4'd12: subword_in = {w_q[55][23:0], w_q[55][31:24]};
            default: subword_in = 32'h0;
        endcase
    end

    // Rcon decode for even steps
    logic [7:0] rcon;
    assign rcon = 8'h01 << step_q[3:1];

    always @(*) begin
        state_d = state_q;
        step_d  = step_q;
        for (int i = 0; i < 60; i++) begin
            w_d[i] = w_q[i];
        end

        case (state_q)
            IDLE: begin
                if (start_i) begin
                    // Load initial key words
                    w_d[0] = key_i[255:224];
                    w_d[1] = key_i[223:192];
                    w_d[2] = key_i[191:160];
                    w_d[3] = key_i[159:128];
                    w_d[4] = key_i[127:96];
                    w_d[5] = key_i[95:64];
                    w_d[6] = key_i[63:32];
                    w_d[7] = key_i[31:0];
                    step_d = 4'd0;
                    state_d = EXPAND;
                end
            end

            EXPAND: begin
                // Compute next 4 words using purely static index mapping and feed-forward expressions (no self-reads of w_d)
                case (step_q)
                    4'd0: begin
                        w_d[8]  = w_q[0] ^ subword_out ^ {rcon, 24'b0};
                        w_d[9]  = w_q[1] ^ w_q[0] ^ subword_out ^ {rcon, 24'b0};
                        w_d[10] = w_q[2] ^ w_q[1] ^ w_q[0] ^ subword_out ^ {rcon, 24'b0};
                        w_d[11] = w_q[3] ^ w_q[2] ^ w_q[1] ^ w_q[0] ^ subword_out ^ {rcon, 24'b0};
                    end
                    4'd1: begin
                        w_d[12] = w_q[4] ^ subword_out;
                        w_d[13] = w_q[5] ^ w_q[4] ^ subword_out;
                        w_d[14] = w_q[6] ^ w_q[5] ^ w_q[4] ^ subword_out;
                        w_d[15] = w_q[7] ^ w_q[6] ^ w_q[5] ^ w_q[4] ^ subword_out;
                    end
                    4'd2: begin
                        w_d[16] = w_q[8] ^ subword_out ^ {rcon, 24'b0};
                        w_d[17] = w_q[9] ^ w_q[8] ^ subword_out ^ {rcon, 24'b0};
                        w_d[18] = w_q[10] ^ w_q[9] ^ w_q[8] ^ subword_out ^ {rcon, 24'b0};
                        w_d[19] = w_q[11] ^ w_q[10] ^ w_q[9] ^ w_q[8] ^ subword_out ^ {rcon, 24'b0};
                    end
                    4'd3: begin
                        w_d[20] = w_q[12] ^ subword_out;
                        w_d[21] = w_q[13] ^ w_q[12] ^ subword_out;
                        w_d[22] = w_q[14] ^ w_q[13] ^ w_q[12] ^ subword_out;
                        w_d[23] = w_q[15] ^ w_q[14] ^ w_q[13] ^ w_q[12] ^ subword_out;
                    end
                    4'd4: begin
                        w_d[24] = w_q[16] ^ subword_out ^ {rcon, 24'b0};
                        w_d[25] = w_q[17] ^ w_q[16] ^ subword_out ^ {rcon, 24'b0};
                        w_d[26] = w_q[18] ^ w_q[17] ^ w_q[16] ^ subword_out ^ {rcon, 24'b0};
                        w_d[27] = w_q[19] ^ w_q[18] ^ w_q[17] ^ w_q[16] ^ subword_out ^ {rcon, 24'b0};
                    end
                    4'd5: begin
                        w_d[28] = w_q[20] ^ subword_out;
                        w_d[29] = w_q[21] ^ w_q[20] ^ subword_out;
                        w_d[30] = w_q[22] ^ w_q[21] ^ w_q[20] ^ subword_out;
                        w_d[31] = w_q[23] ^ w_q[22] ^ w_q[21] ^ w_q[20] ^ subword_out;
                    end
                    4'd6: begin
                        w_d[32] = w_q[24] ^ subword_out ^ {rcon, 24'b0};
                        w_d[33] = w_q[25] ^ w_q[24] ^ subword_out ^ {rcon, 24'b0};
                        w_d[34] = w_q[26] ^ w_q[25] ^ w_q[24] ^ subword_out ^ {rcon, 24'b0};
                        w_d[35] = w_q[27] ^ w_q[26] ^ w_q[25] ^ w_q[24] ^ subword_out ^ {rcon, 24'b0};
                    end
                    4'd7: begin
                        w_d[36] = w_q[28] ^ subword_out;
                        w_d[37] = w_q[29] ^ w_q[28] ^ subword_out;
                        w_d[38] = w_q[30] ^ w_q[29] ^ w_q[28] ^ subword_out;
                        w_d[39] = w_q[31] ^ w_q[30] ^ w_q[29] ^ w_q[28] ^ subword_out;
                    end
                    4'd8: begin
                        w_d[40] = w_q[32] ^ subword_out ^ {rcon, 24'b0};
                        w_d[41] = w_q[33] ^ w_q[32] ^ subword_out ^ {rcon, 24'b0};
                        w_d[42] = w_q[34] ^ w_q[33] ^ w_q[32] ^ subword_out ^ {rcon, 24'b0};
                        w_d[43] = w_q[35] ^ w_q[34] ^ w_q[33] ^ w_q[32] ^ subword_out ^ {rcon, 24'b0};
                    end
                    4'd9: begin
                        w_d[44] = w_q[36] ^ subword_out;
                        w_d[45] = w_q[37] ^ w_q[36] ^ subword_out;
                        w_d[46] = w_q[38] ^ w_q[37] ^ w_q[36] ^ subword_out;
                        w_d[47] = w_q[39] ^ w_q[38] ^ w_q[37] ^ w_q[36] ^ subword_out;
                    end
                    4'd10: begin
                        w_d[48] = w_q[40] ^ subword_out ^ {rcon, 24'b0};
                        w_d[49] = w_q[41] ^ w_q[40] ^ subword_out ^ {rcon, 24'b0};
                        w_d[50] = w_q[42] ^ w_q[41] ^ w_q[40] ^ subword_out ^ {rcon, 24'b0};
                        w_d[51] = w_q[43] ^ w_q[42] ^ w_q[41] ^ w_q[40] ^ subword_out ^ {rcon, 24'b0};
                    end
                    4'd11: begin
                        w_d[52] = w_q[44] ^ subword_out;
                        w_d[53] = w_q[45] ^ w_q[44] ^ subword_out;
                        w_d[54] = w_q[46] ^ w_q[45] ^ w_q[44] ^ subword_out;
                        w_d[55] = w_q[47] ^ w_q[46] ^ w_q[45] ^ w_q[44] ^ subword_out;
                    end
                    4'd12: begin
                        w_d[56] = w_q[48] ^ subword_out ^ {rcon, 24'b0};
                        w_d[57] = w_q[49] ^ w_q[48] ^ subword_out ^ {rcon, 24'b0};
                        w_d[58] = w_q[50] ^ w_q[49] ^ w_q[48] ^ subword_out ^ {rcon, 24'b0};
                        w_d[59] = w_q[51] ^ w_q[50] ^ w_q[49] ^ w_q[48] ^ subword_out ^ {rcon, 24'b0};
                    end
                    default: ;
                endcase

                if (step_q == 4'd12) begin
                    state_d = DONE;
                end else begin
                    step_d = step_q + 4'd1;
                end
            end

            DONE: begin
                if (start_i) begin
                    // Load initial key words
                    w_d[0] = key_i[255:224];
                    w_d[1] = key_i[223:192];
                    w_d[2] = key_i[191:160];
                    w_d[3] = key_i[159:128];
                    w_d[4] = key_i[127:96];
                    w_d[5] = key_i[95:64];
                    w_d[6] = key_i[63:32];
                    w_d[7] = key_i[31:0];
                    step_d = 4'd0;
                    state_d = EXPAND;
                end else begin
                    state_d = IDLE;
                end
            end

            default: state_d = IDLE;
        endcase
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_q <= IDLE;
            step_q  <= 4'd0;
            for (int i = 0; i < 60; i++) begin
                w_q[i] <= 32'h0;
            end
        end else begin
            state_q <= state_d;
            step_q  <= step_d;
            for (int i = 0; i < 60; i++) begin
                w_q[i] <= w_d[i];
            end
        end
    end

    assign ready_o = (state_q == IDLE);
    assign done_o  = (state_q == DONE);

    genvar rk;
    generate
        for (rk = 0; rk <= 14; rk++) begin : gen_rk
            assign round_keys_o[rk] = {w_q[4*rk], w_q[4*rk+1], w_q[4*rk+2], w_q[4*rk+3]};
        end
    endgenerate

endmodule
