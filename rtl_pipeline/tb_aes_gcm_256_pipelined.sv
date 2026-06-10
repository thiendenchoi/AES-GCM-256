`timescale 1ns/1ps

module tb_aes_gcm_256_pipelined;

    logic         clk;
    logic         rst_n;
    logic         start;
    logic         ready;
    logic         done;

    logic [255:0] key;
    logic [95:0]  iv;
    logic [63:0]  aad_len;
    logic [63:0]  pt_len;

    logic [127:0] data_in;
    logic         data_val_in;
    logic         data_ready;

    logic [127:0] data_out;
    logic         data_val_out;
    logic [127:0] tag;

    // Instantiate Pipelined GCM module
    aes_gcm_256_pipelined uut (
        .clk(clk),
        .rst_n(rst_n),
        .start_i(start),
        .ready_o(ready),
        .done_o(done),
        .key_i(key),
        .iv_i(iv),
        .aad_len_i(aad_len),
        .pt_len_i(pt_len),
        .data_i(data_in),
        .data_val_i(data_val_in),
        .data_ready_o(data_ready),
        .data_o(data_out),
        .data_val_o(data_val_out),
        .tag_o(tag)
    );

    // Clock generator (156.25 MHz -> 6.4ns period)
    initial begin
        clk = 0;
        forever #3.2 clk = ~clk;
    end

    // Flush stdout periodically
    initial begin
        forever begin
            #100;
            $fflush();
        end
    end

    // Trace intermediate GCM steps
    always @(posedge clk) begin
        $display("[DEBUG] Time=%0t | state=%0d | aes_val_in=%b | aes_val_out=%b | aes_in_cnt=%d | aes_out_cnt=%d | ghash_out_cnt=%d | data_ready=%b | data_val_i=%b | stall_aes=%b",
                 $time, uut.state_q, uut.aes_valid_in, uut.aes_valid_out, uut.aes_in_cnt_q, uut.aes_out_cnt_q, uut.ghash_out_cnt_q, data_ready, uut.data_val_i, uut.stall_aes);
        if (rst_n) begin
            // Key expansion
            if (uut.state_q == uut.LOAD_KEY && uut.aes_key_ready) begin
                $display("[TRACE] Step 0 (Key Expansion): Completed successfully.");
            end

            // Subkey H and J0
            if (uut.state_q == uut.CALC_H && uut.aes_valid_out) begin
                $display("[TRACE] Step 1 (Subkey H):      H = AES(K, 0) = %h", uut.aes_data_out);
                $display("[TRACE] Step 2 (Init J0):       J0 = IV || 32'd1 = %h", {uut.iv_q, 32'd1});
            end

            // Counter block encryption
            if (uut.state_q == uut.PT_PIPE && uut.aes_valid_out) begin
                $display("[TRACE] Step 3 (CTR Enc):       ctr = %h -> Keystream = %h", {uut.iv_q, 32'd2 + uut.aes_out_cnt_q[31:0]}, uut.aes_data_out);
            end

            // Plaintext XOR with Keystream
            if (uut.state_q == uut.PT_PIPE && uut.aes_valid_out && uut.data_val_i) begin
                $display("[TRACE] Step 4 (Data XOR):      Plaintext = %h -> Ciphertext = %h", uut.data_i, uut.aes_data_out ^ uut.data_i);
            end

            // GHASH accumulator for Plaintext/Ciphertext
            if (uut.state_q == uut.PT_PIPE && uut.ghash_valid_out) begin
                $display("[TRACE] Step 5 (GHASH block):   Accumulator Y = %h", uut.ghash_z);
            end

            // GHASH accumulator for AAD
            if (uut.state_q == uut.AAD_HASH && uut.ghash_valid_out) begin
                $display("[TRACE] Step 5 (GHASH AAD):     Accumulator Y = %h", uut.ghash_z);
            end

            // GHASH accumulator for Length block
            if (uut.state_q == uut.CALC_L && uut.ghash_valid_out) begin
                $display("[TRACE] Step 6 (GHASH Lengths): AAD_len_bits || PT_len_bits = %h -> Accumulator Y = %h", 
                         {uut.aad_len_q[60:0], 3'b0, uut.pt_len_q[60:0], 3'b0}, uut.ghash_z);
            end

            // EJ0 Encryption
            if (uut.state_q == uut.CALC_TAG_ENC && uut.aes_valid_out) begin
                $display("[TRACE] Step 7 (Tag Enc):       EJ0 = AES(K, J0) = %h", uut.aes_data_out);
            end
        end
    end

    // Monitor trace
    initial begin
        $monitor("Time=%0td | rst_n=%b | state=%0d | ready=%b | start=%b | data_ready=%b | done=%b",
                 $time, rst_n, uut.state_q, ready, start, data_ready, done);
    end

    // Test sequence
    initial begin
        $dumpfile("tb_aes_gcm_256_pipelined.vcd");
        $dumpvars(0, tb_aes_gcm_256_pipelined);

        $display("==================================================================");
        $display("  AES-GCM-256 Pipelined Simulation Testbench");
        $display("==================================================================");

        // ==================================================================
        // STARTING TEST CASE 1
        // ==================================================================
        $display("\n========================================================");
        $display("  STARTING TEST CASE 1");
        $display("========================================================");
        rst_n       = 0;
        start       = 0;
        data_in     = 128'h0;
        data_val_in = 0;
        #40;
        rst_n = 1;
        #40;

        wait(ready == 1'b1);
        @(posedge clk);
        #1;

        $display("[TB] Starting GCM encryption...");
        key = 256'h0;
        iv = 96'h0;
        aad_len = 64'd0;
        pt_len = 64'd16;
        start = 1;
        @(posedge clk);
        #1;
        start = 0;

        wait(data_ready == 1'b1);
        @(posedge clk);
        #1;
        data_in = 128'h0;
        data_val_in = 1;
        $display("[TB] Fed Plaintext block 1: %h", data_in);

        wait(data_val_out == 1'b1);
        $display("[TB] Received Ciphertext block 1: %h", data_out);
        @(posedge clk);
        #1;
        data_val_in = 0;

        wait(done == 1'b1);
        $display("[TB] Received Tag T: %h", tag);
        $display("========================================================");

        #100;

        // ==================================================================
        // STARTING TEST CASE 2
        // ==================================================================
        $display("\n========================================================");
        $display("  STARTING TEST CASE 2");
        $display("========================================================");
        rst_n       = 0;
        start       = 0;
        data_in     = 128'h0;
        data_val_in = 0;
        #40;
        rst_n = 1;
        #40;

        wait(ready == 1'b1);
        @(posedge clk);
        #1;

        $display("[TB] Starting GCM encryption...");
        key = 256'hfeffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308;
        iv = 96'hcafebabefacedbaddecaf888;
        aad_len = 64'd0;
        pt_len = 64'd64;
        start = 1;
        @(posedge clk);
        #1;
        start = 0;

        // Feed block 1
        wait(data_ready == 1'b1);
        @(posedge clk);
        #1;
        data_in = 128'hd9313225f88406e5a55909c5aff5269a;
        data_val_in = 1;
        $display("[TB] Fed Plaintext block 1: %h", data_in);
        wait(data_val_out == 1'b1);
        $display("[TB] Received Ciphertext block 1: %h", data_out);
        @(posedge clk);
        #1;
        data_val_in = 0;

        // Feed block 2
        wait(data_ready == 1'b1);
        @(posedge clk);
        #1;
        data_in = 128'h86a7a9531534f7da2e4c303d8a318a72;
        data_val_in = 1;
        $display("[TB] Fed Plaintext block 2: %h", data_in);
        wait(data_val_out == 1'b1);
        $display("[TB] Received Ciphertext block 2: %h", data_out);
        @(posedge clk);
        #1;
        data_val_in = 0;

        // Feed block 3
        wait(data_ready == 1'b1);
        @(posedge clk);
        #1;
        data_in = 128'h1c3c0c95956809532fcf0e2449a6b525;
        data_val_in = 1;
        $display("[TB] Fed Plaintext block 3: %h", data_in);
        wait(data_val_out == 1'b1);
        $display("[TB] Received Ciphertext block 3: %h", data_out);
        @(posedge clk);
        #1;
        data_val_in = 0;

        // Feed block 4
        wait(data_ready == 1'b1);
        @(posedge clk);
        #1;
        data_in = 128'hb16aedf5aa0de657ba637b391aafd255;
        data_val_in = 1;
        $display("[TB] Fed Plaintext block 4: %h", data_in);
        wait(data_val_out == 1'b1);
        $display("[TB] Received Ciphertext block 4: %h", data_out);
        @(posedge clk);
        #1;
        data_val_in = 0;

        wait(done == 1'b1);
        $display("[TB] Received Tag T: %h", tag);
        $display("========================================================");

        #100;

        // ==================================================================
        // STARTING TEST CASE 3
        // ==================================================================
        $display("\n========================================================");
        $display("  STARTING TEST CASE 3");
        $display("========================================================");
        rst_n       = 0;
        start       = 0;
        data_in     = 128'h0;
        data_val_in = 0;
        #40;
        rst_n = 1;
        #40;

        wait(ready == 1'b1);
        @(posedge clk);
        #1;

        $display("[TB] Starting GCM encryption...");
        key = 256'hfeffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308;
        iv = 96'hcafebabefacedbaddecaf888;
        aad_len = 64'd20;
        pt_len = 64'd60;
        start = 1;
        @(posedge clk);
        #1;
        start = 0;

        // Feed AAD block 1
        wait(data_ready == 1'b1);
        @(posedge clk);
        #1;
        data_in = 128'hfeedfacedeadbeeffeedfacedeadbeef;
        data_val_in = 1;
        $display("[TB] Fed AAD block 1: %h", data_in);
        @(posedge clk);
        #1;
        data_val_in = 0;

        // Feed AAD block 2
        wait(data_ready == 1'b1);
        @(posedge clk);
        #1;
        data_in = 128'habaddad2000000000000000000000000;
        data_val_in = 1;
        $display("[TB] Fed AAD block 2: %h", data_in);
        @(posedge clk);
        #1;
        data_val_in = 0;

        // Feed PT block 1
        wait(data_ready == 1'b1);
        @(posedge clk);
        #1;
        data_in = 128'hd9313225f88406e5a55909c5aff5269a;
        data_val_in = 1;
        $display("[TB] Fed Plaintext block 1: %h", data_in);
        wait(data_val_out == 1'b1);
        $display("[TB] Received Ciphertext block 1: %h", data_out);
        @(posedge clk);
        #1;
        data_val_in = 0;

        // Feed PT block 2
        wait(data_ready == 1'b1);
        @(posedge clk);
        #1;
        data_in = 128'h86a7a9531534f7da2e4c303d8a318a72;
        data_val_in = 1;
        $display("[TB] Fed Plaintext block 2: %h", data_in);
        wait(data_val_out == 1'b1);
        $display("[TB] Received Ciphertext block 2: %h", data_out);
        @(posedge clk);
        #1;
        data_val_in = 0;

        // Feed PT block 3
        wait(data_ready == 1'b1);
        @(posedge clk);
        #1;
        data_in = 128'h1c3c0c95956809532fcf0e2449a6b525;
        data_val_in = 1;
        $display("[TB] Fed Plaintext block 3: %h", data_in);
        wait(data_val_out == 1'b1);
        $display("[TB] Received Ciphertext block 3: %h", data_out);
        @(posedge clk);
        #1;
        data_val_in = 0;

        // Feed PT block 4
        wait(data_ready == 1'b1);
        @(posedge clk);
        #1;
        data_in = 128'hb16aedf5aa0de657ba637b3900000000;
        data_val_in = 1;
        $display("[TB] Fed Plaintext block 4: %h", data_in);
        wait(data_val_out == 1'b1);
        $display("[TB] Received Ciphertext block 4: %h", data_out);
        @(posedge clk);
        #1;
        data_val_in = 0;

        wait(done == 1'b1);
        $display("[TB] Received Tag T: %h", tag);
        $display("========================================================");

        #100;
        $finish;
    end

endmodule
