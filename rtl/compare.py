import subprocess
import re
import sys
import os

def run_cmd(cmd):
    is_windows = sys.platform.startswith('win')
    if not is_windows:
        # Strip 'wsl ' from beginning if running natively under Linux/WSL
        if cmd.startswith('wsl '):
            cmd = cmd[4:]
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.returncode, result.stdout, result.stderr

def main():
    banner = "=========================================================="
    print(banner)
    print("   AES-GCM-256 Automated RTL vs C Verification Tool")
    print(banner)
    
    # 1. Compile and Run C Implementation
    print("[1/4] Compiling pedagogical C implementation...")
    # Try compiling using gcc in WSL
    c_source = "../aes_gcm.c" if os.path.exists("../aes_gcm.c") else "aes_gcm.c"
    code, out, err = run_cmd(f"wsl gcc -O2 {c_source} -o ./aes_gcm_c")
    if code != 0:
        print(f"Error compiling C program in WSL: {err}")
        print("Falling back to local compiler search (gcc)...")
        code, out, err = run_cmd(f"gcc -O2 {c_source} -o aes_gcm_c")
        if code != 0:
            print(f"Failed to compile C program locally: {err}")
            sys.exit(1)
    
    print("[2/4] Running C implementation...")
    code, c_out, err = run_cmd("wsl ./aes_gcm_c")
    if code != 0:
        code, c_out, err = run_cmd("aes_gcm_c")
        if code != 0:
            print(f"Error running C program: {err}")
            sys.exit(1)

    # 2. Compile and Run RTL Implementation
    print("[3/4] Compiling RTL implementation via iverilog...")
    code, out, err = run_cmd("wsl iverilog -g2012 -o sim.out *.sv")
    if code != 0:
        print(f"Error compiling RTL: {err}")
        sys.exit(1)

    print("[4/4] Running RTL simulation...")
    code, rtl_out, err = run_cmd("wsl vvp sim.out")
    if code != 0:
        print(f"Error running RTL simulation: {err}")
        sys.exit(1)

    # 3. Parse C Output
    c_vals = {}
    
    # Extract H
    m = re.search(r"H \(hash subkey\)\s*:\s*([0-9a-fA-F]+)", c_out)
    if m: c_vals['H'] = m.group(1).lower()
    
    # Extract J0
    m = re.search(r"J0\s*:\s*([0-9a-fA-F]+)", c_out)
    if m: c_vals['J0'] = m.group(1).lower()
    
    # Extract CTR Keystream block
    aes_outputs = re.findall(r">>> AES-256 output\s*:\s*([0-9a-fA-F]+)", c_out)
    if len(aes_outputs) >= 2:
        c_vals['ks'] = aes_outputs[1].lower()
    else:
        m = re.search(r"Keystream block \(AES out\)\s*:\s*([0-9a-fA-F]+)", c_out)
        if m: c_vals['ks'] = m.group(1).lower()

    # Extract Ciphertext
    m = re.search(r"Ciphertext block\s*:\s*([0-9a-fA-F]+)", c_out)
    if m: c_vals['CT'] = m.group(1).lower()
    
    # Extract GHASH steps
    ghash_steps = re.findall(r"Result Y_i\s*:\s*([0-9a-fA-F]+)", c_out)
    if len(ghash_steps) >= 2:
        c_vals['GHASH_CT'] = ghash_steps[0].lower() 
        c_vals['GHASH_L'] = ghash_steps[1].lower()  
    elif len(ghash_steps) == 1:
        c_vals['GHASH_CT'] = ghash_steps[0].lower()
    
    # Extract EJ0
    m = re.search(r"AES_K\(J0\)\s*:\s*([0-9a-fA-F]+)", c_out)
    if m: c_vals['EJ0'] = m.group(1).lower()
    
    # Extract Tag
    m = re.search(r">>> Tag T\s*:\s*([0-9a-fA-F]+)", c_out)
    if m: c_vals['Tag'] = m.group(1).lower()

    # 4. Parse RTL Output
    rtl_vals = {}
    
    # Trace H
    m = re.search(r"Step 1 \(Subkey H\):\s*H = AES\(K, 0\) = ([0-9a-fA-F]+)", rtl_out)
    if m: rtl_vals['H'] = m.group(1).lower()
    
    # Trace J0
    m = re.search(r"Step 2 \(Init J0\):\s*J0 = IV \|\| 32'd1 = ([0-9a-fA-F]+)", rtl_out)
    if m: rtl_vals['J0'] = m.group(1).lower()
    
    # Trace Keystream
    m = re.search(r"Step 3 \(CTR Enc\):\s*ctr = [0-9a-fA-F]+ -> Keystream = ([0-9a-fA-F]+)", rtl_out)
    if m: rtl_vals['ks'] = m.group(1).lower()
    
    # Trace CT
    m = re.search(r"Step 4 \(Data XOR\):\s*Plaintext = [0-9a-fA-F]+ -> Ciphertext = ([0-9a-fA-F]+)", rtl_out)
    if m: rtl_vals['CT'] = m.group(1).lower()
    
    # Trace GHASH CT
    m = re.search(r"Step 5 \(GHASH block\):\s*Accumulator Y = ([0-9a-fA-F]+)", rtl_out)
    if m: rtl_vals['GHASH_CT'] = m.group(1).lower()
    
    # Trace GHASH L
    m = re.search(r"Step 6 \(GHASH Lengths\):\s*.* -> Accumulator Y = ([0-9a-fA-F]+)", rtl_out)
    if m: rtl_vals['GHASH_L'] = m.group(1).lower()
    
    # Trace EJ0
    m = re.search(r"Step 7 \(Tag Enc\):\s*EJ0 = AES\(K, J0\) = ([0-9a-fA-F]+)", rtl_out)
    if m: rtl_vals['EJ0'] = m.group(1).lower()
    
    # Trace Tag
    m = re.search(r"Received Tag:\s*([0-9a-fA-F]+)", rtl_out)
    if m: rtl_vals['Tag'] = m.group(1).lower()

    # 5. Print Comparison Table
    print("\n=========================================================================================")
    print("               AES-GCM-256 INTERMEDIATE VALUES COMPARISON (C vs RTL)")
    print("=========================================================================================")
    print(f"{'Intermediate Step':<20} | {'C Program Value':<32} | {'RTL Simulation Value':<32} | {'Match'}")
    print("-" * 97)
    
    steps = [
        ('H (Hash Subkey)', 'H'),
        ('J0 Initialization', 'J0'),
        ('Keystream Block', 'ks'),
        ('Ciphertext Block', 'CT'),
        ('GHASH (Ciphertext)', 'GHASH_CT'),
        ('GHASH (Lengths)', 'GHASH_L'),
        ('EJ0 (Encrypted J0)', 'EJ0'),
        ('Final Tag T', 'Tag')
    ]
    
    all_passed = True
    for label, key_val in steps:
        c_v = c_vals.get(key_val, "MISSING")
        rtl_v = rtl_vals.get(key_val, "MISSING")
        match = "OK" if c_v == rtl_v and c_v != "MISSING" else "FAIL"
        if match == "FAIL":
            all_passed = False
        print(f"{label:<20} | {c_v:<32} | {rtl_v:<32} | {match}")
        
    print("=========================================================================================")
    if all_passed:
        print("\n>>> SUCCESS: RTL results match C results exactly for all intermediate values! <<<")
    else:
        print("\n>>> ERROR: Mismatch detected between RTL and C outputs. <<<")
    print("==========================================================")

if __name__ == '__main__':
    main()
