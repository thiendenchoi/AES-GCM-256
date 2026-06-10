`timescale 1ns/1ps

module tb_aes_gcm_256;

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

    // Instantiate GCM module
    aes_gcm_256_encrypt uut (
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

    // Clock generator (50 MHz / 20ns period)
    initial begin
        clk = 0;
        forever #10 clk = ~clk;
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
        if (rst_n) begin
            // Key expansion
            if (uut.state_q == uut.LOAD_KEY && uut.aes_key_ready) begin
                $display("[TRACE] Step 0 (Key Expansion): Completed successfully.");
            end

            // Subkey H and J0
            if (uut.state_q == uut.CALC_H && uut.aes_done) begin
                $display("[TRACE] Step 1 (Subkey H):      H = AES(K, 0) = %h", uut.aes_data_out);
                $display("[TRACE] Step 2 (Init J0):       J0 = IV || 32'd1 = %h", {uut.iv_q, 32'd1});
            end

            // Counter block encryption
            if (uut.state_q == uut.PT_CTR_ENC && uut.aes_done) begin
                $display("[TRACE] Step 3 (CTR Enc):       ctr = %h -> Keystream = %h", uut.ctr_q, uut.aes_data_out);
            end

            // Plaintext XOR with Keystream
            if (uut.state_q == uut.PT_WAIT_DATA && uut.data_val_i) begin
                $display("[TRACE] Step 4 (Data XOR):      Plaintext = %h -> Ciphertext = %h", uut.data_i, uut.keystream_q ^ uut.data_i);
            end

            // GHASH accumulator for Plaintext/Ciphertext
            if (uut.state_q == uut.PT_HASH && uut.gf_done) begin
                $display("[TRACE] Step 5 (GHASH block):   Accumulator Y = %h", uut.gf_z);
            end

            // GHASH accumulator for AAD
            if (uut.state_q == uut.AAD_HASH && uut.gf_done) begin
                $display("[TRACE] Step 5 (GHASH AAD):     Accumulator Y = %h", uut.gf_z);
            end

            // GHASH accumulator for Length block
            if (uut.state_q == uut.CALC_L && uut.gf_done) begin
                $display("[TRACE] Step 6 (GHASH Lengths): AAD_len_bits || PT_len_bits = %h -> Accumulator Y = %h", 
                         {uut.aad_len_q[60:0], 3'b0, uut.pt_len_q[60:0], 3'b0}, uut.gf_z);
            end

            // EJ0 Encryption
            if (uut.state_q == uut.CALC_TAG_ENC && uut.aes_done) begin
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
        $dumpfile("tb_aes_gcm_256.vcd");
        $dumpvars(0, tb_aes_gcm_256);
        $display("==================================================================");
        $display("  AES-GCM-256 RTL Simulation Testbench");
        $display("  Testing NIST SP 800-38D, Test Case 13");
        $display("==================================================================");

        // Initialization
        rst_n       = 0;
        start       = 0;
        key         = 256'h0;
        iv          = 96'h0;
        aad_len     = 64'd0;
        pt_len      = 64'd16;
        data_in     = 128'h0;
        data_val_in = 0;

        // Reset pulse
        #40;
        rst_n = 1;
        #40;

        // Wait for ready
        wait(ready == 1'b1);
        @(posedge clk);
        #1;

        // Start Encryption
        $display("[TB] Starting GCM encryption...");
        start = 1;
        key   = 256'h0; // All-zero key
        iv    = 96'h0;  // All-zero IV
        aad_len = 64'd0;
        pt_len  = 64'd16; // 16 bytes plaintext
        @(posedge clk);
        #1;
        start = 0;

        // Wait for data_ready to feed Plaintext block
        // (Since aad_len is 0, it will directly go to Plaintext phase)
        $display("[TB] Waiting for data_ready to feed plaintext block...");
        wait(data_ready == 1'b1);
        @(posedge clk);
        #1;
        data_in     = 128'h0; // 16 bytes of zero plaintext
        data_val_in = 1;
        $display("[TB] Fed Plaintext: %h", data_in);

        // Capture ciphertext output (it asserts combinationally when data_val_in is 1)
        wait(data_val_out == 1'b1);
        $display("[TB] Received Ciphertext: %h", data_out);
        if (data_out == 128'hcea7403d4d606b6e074ec5d3baf39d18) begin
            $display("[TB] SUCCESS: Ciphertext matches NIST Test Case 13!");
        end else begin
            $display("[TB] ERROR: Ciphertext mismatch! Expected: cea7403d4d606b6e074ec5d3baf39d18");
        end

        @(posedge clk);
        #1;
        data_val_in = 0;

        // Wait for final tag
        wait(done == 1'b1);
        $display("[TB] Received Tag:        %h", tag);
        if (tag == 128'hd0d1c8a799996bf0265b98b5d48ab919) begin
            $display("[TB] SUCCESS: Tag matches NIST Test Case 13!");
            $display("\n>>> TEST PASSED! <<<");
        end else begin
            $display("[TB] ERROR: Tag mismatch! Expected: d0d1c8a799996bf0265b98b5d48ab919");
            $display("\n>>> TEST FAILED! <<<");
        end

        #100;
        $display("==================================================================");
        $finish;
    end

endmodule
