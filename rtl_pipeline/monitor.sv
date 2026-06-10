module tb_monitor;
    initial begin
        #30000;
        $display("[MONITOR] Timeout reached at 30us. Finishing simulation.");
        $finish;
    end

    always @(posedge tb_throughput.clk) begin
        if (tb_throughput.rst_n) begin
            // Only print every 100 cycles to avoid huge log
            static int cycle = 0;
            cycle++;
            if (cycle % 100 == 0 || tb_throughput.sender_process.sent > 990) begin
                $display("[DEBUG] Time=%0t | state=%0d | aes_val_in=%b | aes_val_out=%b | aes_in_cnt=%0d | aes_out_cnt=%0d | ghash_in=%0d | ghash_out=%0d | data_ready=%b | data_val_in=%b | data_val_out=%b | stall_aes=%b | sent=%0d | received=%0d",
                         $time, 
                         tb_throughput.uut.state_q, 
                         tb_throughput.uut.aes_valid_in, 
                         tb_throughput.uut.aes_valid_out, 
                         tb_throughput.uut.aes_in_cnt_q, 
                         tb_throughput.uut.aes_out_cnt_q, 
                         tb_throughput.uut.ghash_in_cnt_q, 
                         tb_throughput.uut.ghash_out_cnt_q, 
                         tb_throughput.data_ready, 
                         tb_throughput.data_val_in, 
                         tb_throughput.data_val_out, 
                         tb_throughput.uut.stall_aes,
                         tb_throughput.sender_process.sent,
                         tb_throughput.receiver_process.received
                );
            end
        end
    end
endmodule
