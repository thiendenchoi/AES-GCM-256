`timescale 1ns/1ps

module tb_throughput;

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

    // Cycle counter
    integer cycle_count;
    always @(posedge clk) begin
        if (!rst_n)
            cycle_count <= 0;
        else if (start || cycle_count > 0)
            cycle_count <= cycle_count + 1;
    end

    // Test sequence
    initial begin
        $display("==================================================================");
        $display("  AES-GCM-256 Throughput Benchmark (10Gb Ethernet simulation)");
        $display("==================================================================");

        // Reset
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

        // Configuration: 10 blocks of plaintext = 160 bytes
        key = 256'hfeffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308;
        iv = 96'hcafebabefacedbaddecaf888;
        aad_len = 64'd0;
        pt_len = 64'd16000; // 1000 blocks
        
        $display("[TB] Starting GCM throughput test for %0d bytes payload...", pt_len);
        start = 1;
        @(posedge clk);
        #1;
        start = 0;

        // Feed blocks of plaintext concurrently
        fork
            begin : sender_process
                int sent;
                sent = 0;
                data_val_in = 0;
                while (sent < (pt_len >> 4)) begin
                    @(posedge clk);
                    #1;
                    if (data_ready == 1'b1) begin
                        data_in = 128'hd9313225f88406e5a55909c5aff5269a; // dummy plaintext block
                        data_val_in = 1;
                        sent++;
                    end else begin
                        data_val_in = 0;
                    end
                end
                @(posedge clk);
                #1;
                data_val_in = 0;
            end
            begin : receiver_process
                int received;
                received = 0;
                while (received < (pt_len >> 4)) begin
                    wait(data_val_out == 1'b1);
                    @(posedge clk);
                    #1;
                    received++;
                end
            end
        join

        // Wait for GCM completion
        wait(done == 1'b1);
        
        $display("==================================================================");
        $display("  Throughput Results:");
        $display("==================================================================");
        $display("  Total Payload Size: %0d bytes (%0d bits)", pt_len, pt_len * 8);
        $display("  Total Clock Cycles: %0d", cycle_count);
        $display("  Cycles per Block  : %0.2f", real'(cycle_count) / (real'(pt_len) / 16.0));
        $display("  Effective Gbps at 156.25 MHz clock:");
        $display("  Throughput        : %0.2f Gbps", (real'(pt_len * 8) / real'(cycle_count)) * 0.15625);
        $display("==================================================================");

        #100;
        $finish;
    end

endmodule
