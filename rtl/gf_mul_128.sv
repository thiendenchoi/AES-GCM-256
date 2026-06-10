module gf_mul_128 (
    input  logic         clk,
    input  logic         rst_n,
    input  logic         start_i,
    input  logic [127:0] x_i,
    input  logic [127:0] y_i,
    output logic         ready_o,
    output logic         done_o,
    output logic [127:0] z_o
);

    typedef enum logic [1:0] {
        IDLE,
        MULT,
        DONE
    } state_e;

    state_e state_q, state_d;
    logic [6:0]   count_q, count_d;
    logic [127:0] x_q, x_d;
    logic [127:0] v_q, v_d;
    logic [127:0] z_q, z_d;

    always @(*) begin
        state_d = state_q;
        count_d = count_q;
        x_d     = x_q;
        v_d     = v_q;
        z_d     = z_q;

        case (state_q)
            IDLE: begin
                if (start_i) begin
                    x_d     = x_i;
                    v_d     = y_i;
                    z_d     = 128'h0;
                    count_d = 7'd0;
                    state_d = MULT;
                end
            end

            MULT: begin
                // If the current MSB of x is 1, XOR z with v
                if (x_q[127]) begin
                    z_d = z_q ^ v_q;
                end

                // Shift x left by 1 to process the next bit in the next cycle
                x_d = x_q << 1;

                // Shift v right by 1, and conditionally XOR with the GCM polynomial (0xE1 in MSB byte)
                v_d = (v_q >> 1) ^ (v_q[0] ? 128'hE1000000000000000000000000000000 : 128'h0);

                if (count_q == 7'd127) begin
                    state_d = DONE;
                end else begin
                    count_d = count_q + 7'd1;
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
            state_q <= IDLE;
            count_q <= 7'd0;
            x_q     <= 128'h0;
            v_q     <= 128'h0;
            z_q     <= 128'h0;
        end else begin
            state_q <= state_d;
            count_q <= count_d;
            x_q     <= x_d;
            v_q     <= v_d;
            z_q     <= z_d;
        end
    end

    assign z_o     = z_q;
    assign ready_o = (state_q == IDLE);
    assign done_o  = (state_q == DONE);

endmodule
