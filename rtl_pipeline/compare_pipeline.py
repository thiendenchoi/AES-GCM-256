import subprocess
import re
import sys
import os

def run_cmd(cmd):
    is_windows = sys.platform.startswith('win')
    if not is_windows:
        if cmd.startswith('wsl '):
            cmd = cmd[4:]
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.returncode, result.stdout, result.stderr

def main():
    banner = "=========================================================="
    print(banner)
    print("   AES-GCM-256 Pipelined Core Verification & Benchmarking")
    print(banner)
    
    # 1. Compile and Run C Implementation
    print("\n[1/5] Compiling multi-testcase C implementation...")
    c_source = "../aes_gcm_multi.c" if os.path.exists("../aes_gcm_multi.c") else "aes_gcm_multi.c"
    code, out, err = run_cmd(f"wsl gcc -O2 {c_source} -o ./aes_gcm_multi_c")
    if code != 0:
        print(f"Error compiling C program in WSL: {err}")
        print("Falling back to local compiler search (gcc)...")
        code, out, err = run_cmd(f"gcc -O2 {c_source} -o aes_gcm_multi_c")
        if code != 0:
            print(f"Failed to compile C program locally: {err}")
            sys.exit(1)
    
    print("[2/5] Running C implementation...")
    code, c_out, err = run_cmd("wsl ./aes_gcm_multi_c")
    if code != 0:
        code, c_out, err = run_cmd("aes_gcm_multi_c")
        if code != 0:
            print(f"Error running C program: {err}")
            sys.exit(1)

    # 2. Compile and Run AES-256 Pipelined Unit Test
    print("\n[3/5] Verifying Pipelined AES-256 Core Unit Test...")
    aes_rtl_files = "tb_aes_256_pipelined.sv aes_256_pipelined.sv aes_round.sv aes_sbox.sv aes_key_expand_256.sv"
    code, out, err = run_cmd(f"wsl iverilog -g2012 -o sim_aes.out {aes_rtl_files}")
    if code != 0:
        print(f"Error compiling AES RTL: {err}")
        sys.exit(1)
        
    code, aes_out, err = run_cmd("wsl vvp sim_aes.out")
    if code != 0:
        print(f"Error running AES simulation: {err}")
        sys.exit(1)
    print(aes_out)

    # 3. Compile and Run GCM Pipelined Implementation
    print("\n[4/5] Compiling Pipelined AES-GCM-256 Simulation via iverilog...")
    gcm_rtl_files = "tb_aes_gcm_256_pipelined.sv aes_256_pipelined.sv aes_gcm_256_pipelined.sv aes_round.sv aes_sbox.sv aes_key_expand_256.sv gf_mul_128_pipe.sv"
    code, out, err = run_cmd(f"wsl iverilog -g2012 -o sim_gcm.out {gcm_rtl_files}")
    if code != 0:
        print(f"Error compiling GCM RTL: {err}")
        sys.exit(1)

    print("Running GCM simulation...")
    code, rtl_out, err = run_cmd("wsl vvp sim_gcm.out")
    if code != 0:
        print(f"Error running GCM simulation: {err}")
        sys.exit(1)

    # 4. Compile and Run GCM Throughput Benchmark
    print("\n[5/5] Compiling and Running Throughput Benchmark...")
    bench_rtl_files = "tb_throughput.sv aes_256_pipelined.sv aes_gcm_256_pipelined.sv aes_round.sv aes_sbox.sv aes_key_expand_256.sv gf_mul_128_pipe.sv"
    code, out, err = run_cmd(f"wsl iverilog -g2012 -o sim_bench.out {bench_rtl_files}")
    if code != 0:
        print(f"Error compiling Throughput RTL: {err}")
        sys.exit(1)

    code, bench_out, err = run_cmd("wsl vvp sim_bench.out")
    if code != 0:
        print(f"Error running Throughput simulation: {err}")
        sys.exit(1)
    
    # Print benchmark results
    bench_lines = bench_out.split('\n')
    print_bench = False
    for line in bench_lines:
        if "Throughput Results:" in line or print_bench:
            print_bench = True
            print(line)
        if "======" in line and print_bench and "Throughput Results:" not in line:
            # check if it is the closing banner
            if any(char.isalnum() for char in line) == False:
                # it's just a line of '='
                pass

    # 5. Parse C Output
    c_sections = re.split(r"TEST CASE \d", c_out)
    c_results = {}
    for i in range(1, 4):
        if i < len(c_sections):
            sect = c_sections[i]
            vals = {}
            m = re.search(r"H \(hash subkey\)\s*:\s*([0-9a-fA-F]+)", sect)
            if m: vals['H'] = m.group(1).lower()
            m = re.search(r"J0\s*:\s*([0-9a-fA-F]+)", sect)
            if m: vals['J0'] = m.group(1).lower()
            m = re.search(r"Ciphertext\s*:\s*([0-9a-fA-F]+)", sect)
            if m: vals['CT'] = m.group(1).lower()
            m = re.search(r"Tag\s*:\s*([0-9a-fA-F]+)", sect)
            if m: vals['Tag'] = m.group(1).lower()
            c_results[i] = vals

    # 6. Parse RTL Output
    rtl_sections = re.split(r"STARTING TEST CASE \d", rtl_out)
    rtl_results = {}
    expected_ct_lens = {1: 32, 2: 128, 3: 120}
    
    for i in range(1, 4):
        if i < len(rtl_sections):
            sect = rtl_sections[i]
            vals = {}
            m = re.search(r"H = AES\(K, 0\) = ([0-9a-fA-F]+)", sect)
            if m: vals['H'] = m.group(1).lower()
            m = re.search(r"J0 = IV \|\| 32'd1 = ([0-9a-fA-F]+)", sect)
            if m: vals['J0'] = m.group(1).lower()
            ct_blocks = re.findall(r"Received Ciphertext block \d+:\s*([0-9a-fA-F]+)", sect)
            if ct_blocks:
                full_ct = "".join(ct_blocks).lower()
                expected_len = expected_ct_lens[i]
                vals['CT'] = full_ct[:expected_len]
            m = re.search(r"Received Tag T:\s*([0-9a-fA-F]+)", sect)
            if m: vals['Tag'] = m.group(1).lower()
            rtl_results[i] = vals

    # 7. Print Comparison Tables
    all_passed = True
    for tc in range(1, 4):
        print(f"\n=========================================================================================")
        print(f"               TEST CASE {tc} COMPARISON (C vs PIPELINED RTL)")
        print(f"=========================================================================================")
        print(f"{'Field':<18} | {'C Program Value':<32} | {'RTL Simulation Value':<32} | {'Match'}")
        print("-" * 97)
        
        tc_c = c_results.get(tc, {})
        tc_rtl = rtl_results.get(tc, {})
        
        fields = [
            ('H (Hash Subkey)', 'H'),
            ('J0 Vector', 'J0'),
            ('Ciphertext', 'CT'),
            ('Final Tag T', 'Tag')
        ]
        
        tc_passed = True
        for label, field_key in fields:
            val_c = tc_c.get(field_key, "MISSING")
            val_rtl = tc_rtl.get(field_key, "MISSING")
            
            match = "OK" if val_c == val_rtl and val_c != "MISSING" else "FAIL"
            if match == "FAIL":
                tc_passed = False
                all_passed = False
            
            c_disp = val_c if len(val_c) <= 32 else val_c[:29] + "..."
            rtl_disp = val_rtl if len(val_rtl) <= 32 else val_rtl[:29] + "..."
            
            print(f"{label:<18} | {c_disp:<32} | {rtl_disp:<32} | {match}")
            if len(val_c) > 32 or len(val_rtl) > 32:
                idx = 32
                while idx < max(len(val_c), len(val_rtl)):
                    part_c = val_c[idx:idx+32] if idx < len(val_c) else ""
                    part_rtl = val_rtl[idx:idx+32] if idx < len(val_rtl) else ""
                    print(f"{'':<18} | {part_c:<32} | {part_rtl:<32} |")
                    idx += 32
                    
        print("-" * 97)
        if tc_passed:
            print(f"Result for Test Case {tc}: PASSED")
        else:
            print(f"Result for Test Case {tc}: FAILED")
        print("=========================================================================================")

    print("\n==========================================================")
    if all_passed:
        print(">>> SUCCESS: Pipelined RTL results match C results exactly for all 3 Test Cases! <<<")
    else:
        print(">>> ERROR: Mismatches detected in verification. <<<")
    print("==========================================================")

if __name__ == '__main__':
    main()
