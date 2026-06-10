`timescale 1ns/1ps

module tb_aes_256_pipelined;

    logic         clk;
    logic         rst_n;
    logic         en;

    // Key Expansion signals
    logic         load_key;
    logic [255:0] key;
    logic         key_ready;

    // Pipeline Input
    logic [127:0] data_in;
    logic         valid_in;
    logic [15:0]  keep_in;
    logic         last_in;

    // Pipeline Output
    logic [127:0] data_out;
    logic         valid_out;
    logic [15:0]  keep_out;
    logic         last_out;

    // Instantiate Pipelined AES-256 core
    aes_256_pipelined uut (
        .clk(clk),
        .rst_n(rst_n),
        .en_i(en),
        .load_key_i(load_key),
        .key_i(key),
        .key_ready_o(key_ready),
        .data_i(data_in),
        .valid_i(valid_in),
        .keep_i(keep_in),
        .last_i(last_in),
        .data_o(data_out),
        .valid_o(valid_out),
        .keep_o(keep_out),
        .last_o(last_out)
    );

    // Clock generator (156.25 MHz -> 6.4ns period)
    initial begin
        clk = 0;
        forever #3.2 clk = ~clk;
    end

    // Test sequence
    initial begin
        $dumpfile("tb_aes_256_pipelined.vcd");
        $dumpvars(0, tb_aes_256_pipelined);

        $display("==================================================================");
        $display("  AES-256 Pipelined Core Unit Testbench");
        $display("==================================================================");

        // Reset
        rst_n    = 0;
        en       = 1;
        load_key = 0;
        key      = 256'h0;
        data_in  = 128'h0;
        valid_in = 0;
        keep_in  = 16'hFFFF;
        last_in  = 0;
        #20;
        rst_n = 1;
        #20;

        // Load AES-256 Key
        @(posedge clk);
        #0.5;
        key = 256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
        load_key = 1;
        $display("[TB] Loading Key: %h", key);
        @(posedge clk);
        #0.5;
        load_key = 0;

        // Wait for key ready
        wait(key_ready == 1'b1);
        $display("[TB] Key expansion completed. System ready.");
        #10;

        // Feed Plaintext blocks back-to-back (1 block per cycle)
        @(posedge clk);
        #0.5;
        data_in  = 128'h00112233445566778899aabbccddeeff;
        valid_in = 1;
        keep_in  = 16'hFFFF;
        last_in  = 0;
        $display("[TB] Fed block 0: %h", data_in);

        @(posedge clk);
        #0.5;
        data_in  = 128'h123456789abcdef00123456789abcdef;
        valid_in = 1;
        keep_in  = 16'hFFFF;
        last_in  = 0;
        $display("[TB] Fed block 1: %h", data_in);

        @(posedge clk);
        #0.5;
        data_in  = 128'hffffffffffffffffffffffffffffffff;
        valid_in = 1;
        keep_in  = 16'hFFFF;
        last_in  = 1; // Mark last block
        $display("[TB] Fed block 2: %h", data_in);

        // Stop feeding new data
        @(posedge clk);
        #0.5;
        valid_in = 0;
        data_in  = 128'h0;
        last_in  = 0;

        // Monitor outputs
        $display("[TB] Waiting for pipeline outputs (15 cycles latency)...");
        
        // Wait for first output block to emerge (15 clock cycles after block 0 is fed)
        wait(valid_out == 1'b1);
        $display("[TB] Output 0: %h (Expected: 8ea2b7ca516745bfeafc49904b496089)", data_out);
        if (data_out == 128'h8ea2b7ca516745bfeafc49904b496089) begin
            $display("[TB] Block 0 MATCH!");
        end else begin
            $display("[TB] Block 0 MISMATCH!");
        end

        // Next cycle output
        @(posedge clk);
        #0.5;
        $display("[TB] Output 1: %h (Expected cipher value for input 1)", data_out);

        // Next cycle output
        @(posedge clk);
        #0.5;
        $display("[TB] Output 2: %h (Expected cipher value for input 2, last_o=%b)", data_out, last_out);

        #50;
        $finish;
    end

endmodule
