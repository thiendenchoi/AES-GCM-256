/*
 * AES-GCM-256 with full intermediate-value tracing
 * ------------------------------------------------
 * Compiled for 3 Test Cases from thesis.pdf / NIST SP 800-38D
 *
 * Build : gcc -O2 aes_gcm_multi.c -o aes_gcm_multi_c
 * Run   : ./aes_gcm_multi_c
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Pretty printing helpers                                            */
/* ------------------------------------------------------------------ */
static void hex(const char *label, const uint8_t *b, int n) {
    printf("  %-28s : ", label);
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}
static void banner(const char *s) {
    printf("\n==================================================================\n");
    printf("  %s\n", s);
    printf("==================================================================\n");
}
static void sub(const char *s) {
    printf("\n------ %s ------\n", s);
}

/* ------------------------------------------------------------------ */
/*  AES-256 core                                                      */
/* ------------------------------------------------------------------ */
static const uint8_t SBOX[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

static const uint8_t RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static void key_expansion_256(const uint8_t key[32], uint8_t rk[240], int verbose) {
    memcpy(rk, key, 32);
    uint8_t t[4];
    int i = 32, rcon_idx = 1;
    while (i < 240) {
        memcpy(t, rk + i - 4, 4);
        if (i % 32 == 0) {
            uint8_t tmp = t[0];
            t[0] = SBOX[t[1]] ^ RCON[rcon_idx++];
            t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]];
            t[3] = SBOX[tmp];
        } else if (i % 32 == 16) {
            for (int j = 0; j < 4; j++) t[j] = SBOX[t[j]];
        }
        for (int j = 0; j < 4; j++) rk[i + j] = rk[i + j - 32] ^ t[j];
        i += 4;
    }
    if (verbose) {
        sub("Key expansion: 15 round keys");
        for (int r = 0; r <= 14; r++) {
            char lbl[32]; snprintf(lbl, sizeof lbl, "RoundKey[%2d]", r);
            hex(lbl, rk + r * 16, 16);
        }
    }
}

static void sub_bytes(uint8_t s[16]) {
    for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]];
}
static void shift_rows(uint8_t s[16]) {
    uint8_t t;
    t = s[1];  s[1]  = s[5];  s[5]  = s[9];  s[9]  = s[13]; s[13] = t;
    t = s[2];  s[2]  = s[10]; s[10] = t;
    t = s[6];  s[6]  = s[14]; s[14] = t;
    t = s[3];  s[3]  = s[15]; s[15] = s[11]; s[11] = s[7];  s[7]  = t;
}
static void mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t *col = s + 4 * c;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        uint8_t h = a0 ^ a1 ^ a2 ^ a3;
        col[0] ^= h ^ xtime(a0 ^ a1);
        col[1] ^= h ^ xtime(a1 ^ a2);
        col[2] ^= h ^ xtime(a2 ^ a3);
        col[3] ^= h ^ xtime(a3 ^ a0);
    }
}
static void add_round_key(uint8_t s[16], const uint8_t *rk) {
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
}

static void aes256_encrypt_block(const uint8_t in[16], uint8_t out[16],
                                 const uint8_t rk[240], int verbose,
                                 const char *block_label) {
    uint8_t s[16];
    memcpy(s, in, 16);

    if (verbose) {
        sub(block_label);
        hex("Plaintext block (state)", s, 16);
        hex("AddRoundKey RK[0]      ", rk, 16);
    }
    add_round_key(s, rk);
    if (verbose) hex("State after AddRoundKey", s, 16);

    for (int round = 1; round <= 13; round++) {
        if (verbose) printf("\n  -- Round %2d --\n", round);
        sub_bytes(s);
        if (verbose) hex("After SubBytes", s, 16);
        shift_rows(s);
        if (verbose) hex("After ShiftRows", s, 16);
        mix_columns(s);
        if (verbose) hex("After MixColumns", s, 16);
        if (verbose) { char l[24]; snprintf(l,sizeof l,"RoundKey[%2d]", round); hex(l, rk+round*16, 16); }
        add_round_key(s, rk + round * 16);
        if (verbose) hex("After AddRoundKey", s, 16);
    }

    if (verbose) printf("\n  -- Round 14 (final, no MixColumns) --\n");
    sub_bytes(s);
    if (verbose) hex("After SubBytes", s, 16);
    shift_rows(s);
    if (verbose) hex("After ShiftRows", s, 16);
    add_round_key(s, rk + 14 * 16);
    if (verbose) hex("After AddRoundKey RK[14]", s, 16);

    memcpy(out, s, 16);
    if (verbose) hex(">>> AES-256 output    ", out, 16);
}

/* ------------------------------------------------------------------ */
/*  GHASH                                                             */
/* ------------------------------------------------------------------ */
static void gf128_mul(const uint8_t X[16], const uint8_t Y[16], uint8_t Z[16],
                      int verbose, int step_index) {
    uint8_t V[16];
    uint8_t Zout[16] = {0};
    memcpy(V, Y, 16);

    for (int i = 0; i < 128; i++) {
        int byte = i / 8;
        int bit  = 7 - (i % 8);
        if ((X[byte] >> bit) & 1) {
            for (int j = 0; j < 16; j++) Zout[j] ^= V[j];
        }
        int lsb = V[15] & 1;
        for (int j = 15; j > 0; j--) V[j] = (uint8_t)((V[j] >> 1) | (V[j-1] << 7));
        V[0] >>= 1;
        if (lsb) V[0] ^= 0xe1;
    }
    memcpy(Z, Zout, 16);
    if (verbose) {
        printf("\n  GHASH step %d  (Y_i = (Y_{i-1} XOR X_i) * H)\n", step_index);
        hex("Input block X_i  ", X, 16);
        hex("Current H        ", Y, 16);
        hex("Result Y_i       ", Z, 16);
    }
}

static void inc32(uint8_t c[16]) {
    for (int i = 15; i >= 12; i--) {
        if (++c[i]) break;
    }
}

static void aes_gcm_256_encrypt(
    const uint8_t key[32],
    const uint8_t iv[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *pt,  size_t pt_len,
    uint8_t       *ct,
    uint8_t        tag[16])
{
    uint8_t rk[240];

    banner("STEP 1  —  Inputs");
    hex("Key (256-bit)", key, 32);
    hex("IV  (96-bit) ", iv, 12);
    hex("AAD          ", aad, (int)aad_len);
    hex("Plaintext    ", pt,  (int)pt_len);

    banner("STEP 2  —  AES-256 key expansion");
    key_expansion_256(key, rk, 1);

    banner("STEP 3  —  Hash subkey  H = AES_K(0^128)");
    uint8_t zero[16] = {0};
    uint8_t H[16];
    aes256_encrypt_block(zero, H, rk, 1, "AES-256 on 0^128 to derive H");
    printf("\n");
    hex(">>> H (hash subkey)", H, 16);

    banner("STEP 4  —  Build J0 = IV || 0x00000001");
    uint8_t J0[16];
    memcpy(J0, iv, 12);
    J0[12]=0; J0[13]=0; J0[14]=0; J0[15]=1;
    hex("J0", J0, 16);

    banner("STEP 5  —  CTR-mode encryption of plaintext");
    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    size_t n_blocks = (pt_len + 15) / 16;
    for (size_t b = 0; b < n_blocks; b++) {
        inc32(ctr);
        printf("\n--- CTR block %zu ---\n", b+1);
        hex("Counter value", ctr, 16);

        uint8_t ks[16];
        char lbl[64]; snprintf(lbl,sizeof lbl,"AES-256(Counter %zu)  [round trace only on block 1]", b+1);
        aes256_encrypt_block(ctr, ks, rk, (b == 0), lbl);
        if (b != 0) hex("Keystream block (AES out)", ks, 16);

        size_t off = b * 16;
        size_t this_len = (pt_len - off > 16) ? 16 : (pt_len - off);
        uint8_t pblk[16] = {0}, cblk[16] = {0};
        memcpy(pblk, pt + off, this_len);
        for (size_t i = 0; i < this_len; i++) cblk[i] = pblk[i] ^ ks[i];
        memcpy(ct + off, cblk, this_len);
        hex("Plaintext  block", pblk, (int)this_len);
        hex("Ciphertext block", cblk, (int)this_len);
    }

    banner("STEP 6  —  GHASH over (AAD || Ciphertext || lengths)");
    uint8_t Y[16] = {0};
    int step = 1;

    /* AAD blocks, zero-padded */
    size_t aad_blocks = (aad_len + 15) / 16;
    for (size_t b = 0; b < aad_blocks; b++) {
        uint8_t blk[16] = {0};
        size_t this_len = (aad_len - b*16 > 16) ? 16 : (aad_len - b*16);
        memcpy(blk, aad + b*16, this_len);

        uint8_t tmp[16];
        for (int i = 0; i < 16; i++) tmp[i] = Y[i] ^ blk[i];
        printf("\nAAD block %zu (zero-padded to 128 bits):\n", b+1);
        hex("AAD block      ", blk, 16);
        hex("Y XOR AAD block", tmp, 16);
        gf128_mul(tmp, H, Y, 1, step++);
    }

    /* Ciphertext blocks, zero-padded */
    for (size_t b = 0; b < n_blocks; b++) {
        uint8_t blk[16] = {0};
        size_t this_len = (pt_len - b*16 > 16) ? 16 : (pt_len - b*16);
        memcpy(blk, ct + b*16, this_len);

        uint8_t tmp[16];
        for (int i = 0; i < 16; i++) tmp[i] = Y[i] ^ blk[i];
        printf("\nCiphertext block %zu (zero-padded):\n", b+1);
        hex("CT block       ", blk, 16);
        hex("Y XOR CT block ", tmp, 16);
        gf128_mul(tmp, H, Y, 1, step++);
    }

    /* Length block: 64-bit AAD bitlen || 64-bit CT bitlen */
    uint8_t L[16] = {0};
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits  = (uint64_t)pt_len  * 8;
    for (int i = 0; i < 8; i++) L[7 - i]      = (aad_bits >> (i*8)) & 0xff;
    for (int i = 0; i < 8; i++) L[15 - i]     = (ct_bits  >> (i*8)) & 0xff;

    uint8_t tmp[16];
    for (int i = 0; i < 16; i++) tmp[i] = Y[i] ^ L[i];
    printf("\nLength block (bitlen(AAD) || bitlen(CT)):\n");
    hex("L block        ", L, 16);
    hex("Y XOR L        ", tmp, 16);
    gf128_mul(tmp, H, Y, 1, step++);

    printf("\n");
    hex(">>> S = GHASH result", Y, 16);

    banner("STEP 7  —  Tag = S XOR AES_K(J0)");
    uint8_t EJ0[16];
    aes256_encrypt_block(J0, EJ0, rk, 0, "AES-256(J0)");
    hex("AES_K(J0)", EJ0, 16);
    hex("S        ", Y, 16);
    for (int i = 0; i < 16; i++) tag[i] = Y[i] ^ EJ0[i];
    hex(">>> Tag T", tag, 16);

    banner("FINAL OUTPUT");
    hex("Ciphertext", ct, (int)pt_len);
    hex("Tag       ", tag, 16);
}

int main(void) {
    /* Test Case 1 */
    {
        printf("\n##################################################################\n");
        printf("#  TEST CASE 1 (NIST SP 800-38D, Case 13)                        #\n");
        printf("##################################################################\n");
        uint8_t key[32] = {0};
        uint8_t iv[12]  = {0};
        uint8_t aad[1]  = {0};
        uint8_t pt[16]  = {0};
        uint8_t ct[16], tag[16];

        aes_gcm_256_encrypt(key, iv, aad, 0, pt, 16, ct, tag);
    }

    /* Test Case 2 */
    {
        printf("\n##################################################################\n");
        printf("#  TEST CASE 2 (NIST SP 800-38D, Case 14)                        #\n");
        printf("##################################################################\n");
        uint8_t key[32] = {
            0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
            0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08,
            0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
            0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
        };
        uint8_t iv[12] = {
            0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,
            0xde,0xca,0xf8,0x88
        };
        uint8_t aad[1] = {0};
        uint8_t pt[64] = {
            0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
            0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
            0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
            0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39,0x1a,0xaf,0xd2,0x55
        };
        uint8_t ct[64], tag[16];

        aes_gcm_256_encrypt(key, iv, aad, 0, pt, 64, ct, tag);
    }

    /* Test Case 3 */
    {
        printf("\n##################################################################\n");
        printf("#  TEST CASE 3 (NIST SP 800-38D, Case 15)                        #\n");
        printf("##################################################################\n");
        uint8_t key[32] = {
            0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
            0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08,
            0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
            0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
        };
        uint8_t iv[12] = {
            0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,
            0xde,0xca,0xf8,0x88
        };
        uint8_t aad[20] = {
            0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
            0xab,0xad,0xda,0xd2
        };
        uint8_t pt[60] = {
            0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
            0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
            0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
            0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39
        };
        uint8_t ct[60], tag[16];

        aes_gcm_256_encrypt(key, iv, aad, 20, pt, 60, ct, tag);
    }

    return 0;
}
