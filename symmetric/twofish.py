"""
Twofish Block Cipher
====================
Implemented entirely from scratch. No encryption libraries used.
Only basic Python integer arithmetic, XOR, and bit-shifts.

ACADEMIC REFERENCE
  Schneier, B., Kelsey, J., Whiting, D., Wagner, D., Hall, C. & Ferguson, N. (1998).
  "Twofish: A 128-Bit Block Cipher." Submitted to the AES competition.
  Counterpane Internet Security, Inc.

ALGORITHM CLASS
  Symmetric block cipher — 16-round Feistel network with pre/post whitening

PARAMETERS
  Block size : 128 bits (four 32-bit words)
  Key size   : 128 bits (this implementation; spec supports 192 and 256)
  Rounds     : 16

BANKING USE CASE
  Encrypts account records, balances, and transaction logs stored at rest.
  Data is encrypted with Twofish before being written to accounts.enc on disk.
  A separate Twofish key (the "storage key") is used — not the session key.

WHY TWOFISH OVER AES?
  - Not AES (meets the "other than explained in class" coursework requirement)
  - AES finalist — vetted by the world's top cryptographers
  - Key-dependent S-boxes make it harder to analyse without the key
  - MDS matrix provides provably maximum diffusion per round
  - No known practical attack on full 16-round Twofish (as of 2024)

ARCHITECTURE OVERVIEW
  Twofish has four major components:

  1. KEY SCHEDULE
     Splits the key into "even" (Me) and "odd" (Mo) 32-bit word groups.
     Produces:
       - 40 round subkeys K[0..39] via the h function and PHT
       - 4 S-box key words via the RS (Reed-Solomon) matrix

  2. h FUNCTION (key-dependent S-box application)
     Takes a 32-bit word x and applies a sequence of fixed permutations
     (Q0, Q1) interleaved with XOR against S-box key words.
     Feeds into MDS matrix multiplication for final output.
     This is what makes Twofish's S-boxes KEY-DEPENDENT — unlike AES.

  3. MDS MATRIX (Maximum Distance Separable)
     A 4×4 matrix over GF(2^8) chosen so that every column has MDS
     distance 5. This guarantees that any non-zero input of weight w
     produces output of weight at least 5−w: perfect diffusion.

  4. FEISTEL ROUNDS with PHT
     16 rounds. Each round:
       - Applies h to two 32-bit halves (g function outputs T0, T1)
       - Mixes T0 and T1 via PHT (Pseudo-Hadamard Transform):
           F0 = T0 + T1  +  K[2r+8]
           F1 = T0 + 2T1 +  K[2r+9]
       - XORs F0, F1 into the other two halves (with 1-bit rotations)
       - Swaps all four halves
"""

import struct
import os


# ═══════════════════════════════════════════════════════════════
#  GF(2^8) ARITHMETIC
# ═══════════════════════════════════════════════════════════════

def _gf_mul(a: int, b: int, poly: int = 0x169) -> int:
    """
    Multiply two elements in GF(2^8) — the Galois Field with 256 elements.

    WHAT IS GF(2^8)?
      GF(2^8) is a finite field where elements are 8-bit integers (0..255).
      Addition is XOR (no carries — all arithmetic mod 2).
      Multiplication is polynomial multiplication reduced modulo an
      irreducible polynomial of degree 8.

    THE IRREDUCIBLE POLYNOMIAL (for Twofish's MDS matrix):
      x^8 + x^6 + x^5 + x^3 + 1  represented as binary 101101001 = 0x169
      This polynomial cannot be factored in GF(2) — it is "prime" in GF(2^8).
      Using it guarantees the field structure is well-defined.

    THE ALGORITHM (Russian Peasant Multiplication / "shift-and-XOR"):
      For each bit of b (from LSB to MSB):
        - If the current LSB of b is 1: result XOR= a   (accumulate a into result)
        - Shift a left by 1 (multiply by x)
        - If a's MSB was 1 before shifting: a XOR= (poly & 0xFF)
          (reduce modulo the irreducible polynomial — keeps a in GF(2^8))
        - Shift b right by 1 (advance to next bit)

    WHY THIS MATTERS:
      GF(2^8) multiplication is used in the MDS matrix, which is the
      source of Twofish's diffusion. The MDS property guarantees that
      changing any 1 byte of input changes at least 3 bytes of output.
      This is what prevents statistical patterns from propagating.
    """
    result = 0
    for _ in range(8):
        if b & 1:                     # if current bit of b is set
            result ^= a               # accumulate: result += a (in GF(2^8), + is XOR)
        high_bit = a & 0x80           # check if a is about to overflow 8 bits
        a = (a << 1) & 0xFF           # shift a left (multiply by x) — keep in 8 bits
        if high_bit:
            a ^= (poly & 0xFF)        # reduce: subtract (XOR) the polynomial
        b >>= 1                       # advance to next bit of b
    return result


# ═══════════════════════════════════════════════════════════════
#  FIXED PERMUTATION TABLES  (Q0 and Q1)
# ═══════════════════════════════════════════════════════════════

# Q0 and Q1 are fixed (key-independent) permutation tables used in the
# h function. They provide non-linearity — like S-boxes in AES, but
# simpler and defined by the Twofish specification.
#
# Each table maps 8-bit inputs to 8-bit outputs (a permutation of 0..255).
# They are applied in alternating combinations depending on key size.
# Unlike AES S-boxes (which use GF(2^8) inversion), Q0/Q1 are defined
# by a multi-step mixing procedure described in the Twofish paper.

Q0 = [
    0xA9,0x67,0xB3,0xE8,0x04,0xFD,0xA3,0x76,0x9A,0x92,0x80,0x78,0xE4,0xDD,0xD1,0x38,
    0x0D,0xC6,0x35,0x98,0x18,0xF7,0xEC,0x6C,0x43,0x75,0x37,0x26,0xFA,0x13,0x94,0x48,
    0xF2,0xD0,0x8B,0x30,0x84,0x54,0xDF,0x23,0x19,0x5B,0x3D,0x59,0xF3,0xAE,0xA2,0x82,
    0x63,0x01,0x83,0x2E,0xD9,0x51,0x9B,0x7C,0xA6,0xEB,0xA5,0xBE,0x16,0x0C,0xE3,0x61,
    0xC0,0x8C,0x3A,0xF5,0x73,0x2C,0x25,0x0B,0xBB,0x4E,0x89,0x6B,0x53,0x6A,0xB4,0xF1,
    0xE1,0xE6,0xBD,0x45,0xE2,0xF4,0xB6,0x66,0xCC,0x95,0x03,0x56,0xD4,0x1C,0x1E,0xD7,
    0xFB,0xC3,0x8E,0xB5,0xE9,0xCF,0xBF,0xBA,0xEA,0x77,0x39,0xAF,0x33,0xC9,0x62,0x71,
    0x81,0x79,0x09,0xAD,0x24,0xCD,0xF9,0xD8,0xE5,0xC5,0xB9,0x4D,0x44,0x08,0x86,0xE7,
    0xA1,0x1D,0xAA,0xED,0x06,0x70,0xB2,0xD2,0x41,0x7B,0xA0,0x11,0x31,0xC2,0x27,0x90,
    0x20,0xF6,0x60,0xFF,0x96,0x5C,0xB1,0xAB,0x9E,0x9C,0x52,0x1B,0x5F,0x93,0x0A,0xEF,
    0x91,0x85,0x49,0xEE,0x2D,0x4F,0x8F,0x3B,0x47,0x87,0x6D,0x46,0xD6,0x3E,0x69,0x64,
    0x2A,0xCE,0xCB,0x2F,0xFC,0x97,0x05,0x7A,0xAC,0x7F,0xD5,0x1A,0x4B,0x0E,0xA7,0x5A,
    0x28,0x14,0x3F,0x29,0x88,0x3C,0x4C,0x02,0xB8,0xDA,0xB0,0x17,0x55,0x1F,0x8A,0x7D,
    0x57,0xC7,0x8D,0x74,0xB7,0xC4,0x9F,0x72,0x7E,0x15,0x22,0x12,0x58,0x07,0x99,0x34,
    0x6E,0x50,0xDE,0x68,0x65,0xBC,0xDB,0xF8,0xC8,0xA8,0x2B,0x40,0xDC,0xFE,0x32,0xA4,
    0xCA,0x10,0x21,0xF0,0xD3,0x5D,0x0F,0x00,0x6F,0x9D,0x36,0x42,0x4A,0x5E,0xC1,0xE0,
]

Q1 = [
    0x75,0xF3,0xC6,0xF4,0xDB,0x7B,0xFB,0xC8,0x4A,0xD3,0xE6,0x6B,0x45,0x7D,0xE8,0x4B,
    0xD6,0x32,0xD8,0xFD,0x37,0x71,0xF1,0xE1,0x30,0x0F,0xF8,0x1B,0x87,0xFA,0x06,0x3F,
    0x5E,0xBA,0xAE,0x5B,0x8A,0x00,0xBC,0x9D,0x6D,0xC1,0xB1,0x0E,0x80,0x5D,0xD2,0xD5,
    0xA0,0x84,0x07,0x14,0xB5,0x90,0x2C,0xA3,0xB2,0x73,0x4C,0x54,0x92,0x74,0x36,0x51,
    0x38,0xB0,0xBD,0x5A,0xFC,0x60,0x62,0x96,0x6C,0x42,0xF7,0x10,0x7C,0x28,0x27,0x8C,
    0x13,0x95,0x9C,0xC7,0x24,0x46,0x3B,0x70,0xCA,0xE3,0x85,0xCB,0x11,0xD0,0x93,0xB8,
    0xA6,0x83,0x20,0xFF,0x9F,0x77,0xC3,0xCC,0x03,0x6F,0x08,0xBF,0x40,0xE7,0x2B,0xE2,
    0x79,0x0C,0xAA,0x82,0x41,0x3A,0xEA,0xB9,0xE4,0x9A,0xA4,0x97,0x7E,0xDA,0x7A,0x17,
    0x66,0x94,0xA1,0x1D,0x3D,0xF0,0xDE,0xB3,0x0B,0x72,0xA7,0x1C,0xEF,0xD1,0x53,0x3E,
    0x8F,0x33,0x26,0x5F,0xEC,0x76,0x2A,0x49,0x81,0x88,0xEE,0x21,0xC4,0x1A,0xEB,0xD9,
    0xC5,0x39,0x99,0xCD,0xAD,0x31,0x8B,0x01,0x18,0x23,0xDD,0x1F,0x4E,0x2D,0xF9,0x48,
    0x4F,0xF2,0x65,0x8E,0x78,0x5C,0x58,0x19,0x8D,0xE5,0x98,0x57,0x67,0x7F,0x05,0x64,
    0xAF,0x63,0xB6,0xFE,0xF5,0xB7,0x3C,0xA5,0xCE,0xE9,0x68,0x44,0xE0,0x4D,0x43,0x69,
    0x29,0x2E,0xAC,0x15,0x59,0xA8,0x0A,0x9E,0x6E,0x47,0xDF,0x34,0x35,0x6A,0xCF,0xDC,
    0x22,0xC9,0xC0,0x9B,0x89,0xD4,0xED,0xAB,0x12,0xA2,0x0D,0x52,0xBB,0x02,0x2F,0xA9,
    0xD7,0x61,0x1E,0xB4,0x50,0x04,0xF6,0xC2,0x16,0x25,0x86,0x56,0x55,0x09,0xBE,0x91,
]


# ═══════════════════════════════════════════════════════════════
#  MDS MATRIX
# ═══════════════════════════════════════════════════════════════

MDS = [
    [0x01, 0xEF, 0x5B, 0x5B],
    [0x5B, 0xEF, 0xEF, 0x01],
    [0xEF, 0x5B, 0x01, 0xEF],
    [0xEF, 0x01, 0xEF, 0x5B],
]
# MDS stands for Maximum Distance Separable.
# This 4×4 matrix over GF(2^8) has the property that any non-zero
# vector of weight w maps to output of weight at least (5 − w):
#   weight 1 input → weight ≥ 4 output  (change 1 byte, 4 bytes change)
#   weight 2 input → weight ≥ 3 output
#   weight 3 input → weight ≥ 2 output
#   weight 4 input → weight ≥ 1 output
# This is the best possible diffusion for a 4×4 matrix — "MDS optimal".
# The entries 0x01, 0x5B, 0xEF are specific GF(2^8) elements chosen to
# make the matrix MDS. Verified by the Twofish designers.


def _mds_multiply(v: int) -> int:
    """
    Multiply a 32-bit word by the MDS matrix in GF(2^8).

    Each byte of the 32-bit input corresponds to one row element.
    Multiplying by the 4×4 MDS matrix produces a 32-bit output where
    each output byte depends on ALL four input bytes — maximum diffusion.

    Input v is interpreted as bytes [x0, x1, x2, x3] (little-endian).
    Output y[i] = MDS[i][0]*x0 XOR MDS[i][1]*x1 XOR ... in GF(2^8).
    """
    x = [(v >> (8 * i)) & 0xFF for i in range(4)]   # extract 4 bytes
    y = [0] * 4
    for i in range(4):                               # for each output byte
        for j in range(4):                           # sum contributions
            y[i] ^= _gf_mul(x[j], MDS[i][j])        # GF(2^8) multiply + XOR
    return y[0] | (y[1] << 8) | (y[2] << 16) | (y[3] << 24)


# ═══════════════════════════════════════════════════════════════
#  RS MATRIX  (Reed-Solomon key schedule)
# ═══════════════════════════════════════════════════════════════

RS = [
    [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
    [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
    [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
    [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03],
]
# The RS matrix encodes 8 bytes of key material into 4 bytes.
# It uses a separate irreducible polynomial (0x14D) for the RS field.
# Purpose: derive the S-box key words (S[0..k-1]) from the key bytes.
# The RS encoding gives the S-boxes their key-dependence — the defining
# feature that distinguishes Twofish from AES.

RS_GF_POLY = 0x14D   # x^8 + x^6 + x^3 + x^2 + 1  (for RS field)


def _rs_mul(a: int, b: int) -> int:
    """GF(2^8) multiplication using the RS irreducible polynomial 0x14D."""
    return _gf_mul(a, b, RS_GF_POLY)


def _rs_mds_encode(s0: int, s1: int) -> int:
    """
    Encode 8 bytes of key material through the RS matrix to produce
    one 32-bit S-box key word.

    Each pair of 32-bit key words (s0, s1) maps to one 4-byte S-box key.
    The RS matrix spread ensures that every bit of each S-box key word
    depends on multiple bits of the raw key — diffusion at key setup time.
    """
    r = [0] * 4
    for i in range(4):
        for j in range(8):
            # Treat s0 as bytes 0-3 and s1 as bytes 4-7
            byte = (s0 >> (8 * j)) & 0xFF if j < 4 else (s1 >> (8 * (j - 4))) & 0xFF
            r[i] ^= _rs_mul(RS[i][j], byte)
    return r[0] | (r[1] << 8) | (r[2] << 16) | (r[3] << 24)


# ═══════════════════════════════════════════════════════════════
#  h FUNCTION  (key-dependent S-box)
# ═══════════════════════════════════════════════════════════════

def _h(x: int, L: list, k: int) -> int:
    """
    Twofish's h function: maps a 32-bit word x to a 32-bit output
    using key-dependent S-boxes followed by MDS matrix multiplication.

    HOW KEY-DEPENDENCE WORKS:
      The h function XORs the input with S-box key words (derived from
      the key via the RS matrix) BETWEEN applications of the fixed Q0/Q1
      permutations. This weaves the key into the permutation structure —
      making the effective S-box different for every key.

      Compare to AES: AES S-boxes are FIXED and key-independent.
      Twofish S-boxes are KEY-DEPENDENT — an attacker cannot precompute
      the S-box lookup tables without knowing the key.

    STEPS (for 128-bit key, k=2):
      y ← bytes of x
      y ← Q1[y[0]] ^ L[1][byte0], Q0[y[1]] ^ L[1][byte1], ...  (XOR with key)
      y ← Q1[y[0]], Q0[y[1]], Q1[y[2]], Q0[y[3]]               (fixed perm)
      y ← Q0[y[0]] ^ L[0][byte0], ...                           (XOR with key)
      y ← Q1[y[0]], Q0[y[1]], Q1[y[2]], Q0[y[3]]               (fixed perm)
      output ← MDS_multiply(y)
    """
    y = [(x >> (8 * i)) & 0xFF for i in range(4)]   # split x into 4 bytes

    # For larger keys (192 or 256-bit), additional Q rounds are applied
    if k >= 4:
        y = [Q1[y[0]] ^ ((L[3]      ) & 0xFF),
             Q0[y[1]] ^ ((L[3] >>  8) & 0xFF),
             Q0[y[2]] ^ ((L[3] >> 16) & 0xFF),
             Q1[y[3]] ^ ((L[3] >> 24) & 0xFF)]
    if k >= 3:
        y = [Q1[y[0]] ^ ((L[2]      ) & 0xFF),
             Q1[y[1]] ^ ((L[2] >>  8) & 0xFF),
             Q0[y[2]] ^ ((L[2] >> 16) & 0xFF),
             Q0[y[3]] ^ ((L[2] >> 24) & 0xFF)]

    # For 128-bit key (k=2): two rounds of Q0/Q1 with key XOR
    y = [Q1[Q0[Q0[y[0]] ^ ((L[1]      ) & 0xFF)] ^ ((L[0]      ) & 0xFF)],
         Q0[Q0[Q1[y[1]] ^ ((L[1] >>  8) & 0xFF)] ^ ((L[0] >>  8) & 0xFF)],
         Q1[Q1[Q0[y[2]] ^ ((L[1] >> 16) & 0xFF)] ^ ((L[0] >> 16) & 0xFF)],
         Q0[Q1[Q1[y[3]] ^ ((L[1] >> 24) & 0xFF)] ^ ((L[0] >> 24) & 0xFF)]]

    # Final MDS matrix multiply: provides diffusion across all 4 bytes
    return _mds_multiply(y[0] | (y[1] << 8) | (y[2] << 16) | (y[3] << 24))


# ═══════════════════════════════════════════════════════════════
#  KEY SCHEDULE
# ═══════════════════════════════════════════════════════════════

def _key_schedule(key_bytes: bytes):
    """
    Derive 40 round subkeys K[0..39] and k S-box words from the key.

    WHY 40 SUBKEYS?
      16 rounds × 2 subkeys per round = 32 subkeys for the rounds.
      4 subkeys for input whitening (K[0..3]).
      4 subkeys for output whitening (K[4..7]).
      Total: 40.

    THE SUBKEY GENERATION FORMULA (using PHT — Pseudo-Hadamard Transform):
      RHO = 0x01010101  (a useful constant: all 4 bytes = 0x01)
      For i = 0..19:
        A = h(2i × RHO, Me)         — h applied to even input, even key words
        B = h((2i+1) × RHO, Mo)     — h applied to odd input, odd key words
        B = ROL(B, 8)               — rotate left 8 bits
        K[2i]   = (A + B) mod 2^32  — PHT output 1 (sum)
        K[2i+1] = ROL(A + 2B, 9)    — PHT output 2 (weighted sum, rotated)

    PHT (Pseudo-Hadamard Transform):
      Takes two inputs (a, b) and produces:
        out1 = a + b    (mod 2^32)
        out2 = a + 2b   (mod 2^32)
      This is a linear mixing operation — ensures the two subkeys derived
      from each (A, B) pair are strongly interdependent.
    """
    n = len(key_bytes)
    if n not in (16, 24, 32):
        raise ValueError(
            f"Twofish key must be 16, 24, or 32 bytes. Received {n} bytes.")

    k     = n // 8       # number of 64-bit key "pairs" (2 for 128-bit)
    words = list(struct.unpack(f"<{n // 4}I", key_bytes))

    # Split into "even" and "odd" 32-bit word groups
    Me = [words[2 * i]     for i in range(k)]   # even-indexed words
    Mo = [words[2 * i + 1] for i in range(k)]   # odd-indexed words

    # Encode each (Me[i], Mo[i]) pair through RS matrix → S-box key word
    S = []
    for i in range(k):
        S.append(_rs_mds_encode(Me[i], Mo[i]))
    S.reverse()   # reversed order per Twofish spec

    # Generate 40 round subkeys using h function and PHT
    RHO     = 0x01010101
    subkeys = []
    for i in range(20):
        A  = _h(2 * i * RHO, Me, k)
        B  = _h((2 * i + 1) * RHO, Mo, k)
        B  = ((B << 8) | (B >> 24)) & 0xFFFFFFFF    # ROL(B, 8)
        K0 = (A + B) & 0xFFFFFFFF                    # PHT: sum
        K1 = (A + 2 * B) & 0xFFFFFFFF               # PHT: weighted sum
        K1 = ((K1 << 9) | (K1 >> 23)) & 0xFFFFFFFF  # ROL(K1, 9)
        subkeys.append(K0)
        subkeys.append(K1)

    return subkeys, S, k


# ═══════════════════════════════════════════════════════════════
#  BIT ROTATION HELPERS
# ═══════════════════════════════════════════════════════════════

def _ror32(x: int, n: int) -> int:
    """Rotate x right by n bits within 32-bit range."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _rol32(x: int, n: int) -> int:
    """Rotate x left by n bits within 32-bit range."""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


# ═══════════════════════════════════════════════════════════════
#  BLOCK ENCRYPTION / DECRYPTION
# ═══════════════════════════════════════════════════════════════

def _twofish_encrypt_block(block: bytes, subkeys: list, S: list, k: int) -> bytes:
    """
    Encrypt one 128-bit (16-byte) block through 16 Feistel rounds.

    STRUCTURE OF EACH ROUND r (r = 0..15):

      INPUT : four 32-bit words (R[0], R[1], R[2], R[3])

      Step 1 — g function (h applied to each half-pair):
        T0 = h(R[0], S, k)
        T1 = h(ROL(R[1], 8), S, k)   ← 8-bit rotation before h provides
                                         additional byte-level mixing

      Step 2 — PHT (Pseudo-Hadamard Transform + subkey addition):
        F0 = T0 + T1   + K[2r+8]     ← round subkey for left output
        F1 = T0 + 2T1  + K[2r+9]     ← round subkey for right output

      Step 3 — XOR into opposite halves (with 1-bit rotations):
        R[2] = ROR( R[2] XOR F0, 1 )    ← XOR first, then rotate right
        R[3] = ROL( R[3], 1 ) XOR F1    ← rotate left first, then XOR

      Step 4 — Swap all four words:
        (R[0], R[1], R[2], R[3]) ← (R[2], R[3], R[0], R[1])

    INPUT/OUTPUT WHITENING:
      Before round 0: XOR all four input words with K[0..3]
      After round 15: undo the final swap, then XOR with K[4..7]
      Whitening ensures that without the key, even the first/last
      round cannot be bypassed by an attacker.
    """
    P = list(struct.unpack("<4I", block))

    # Input whitening: XOR each word with a subkey
    # Without this, an attacker knowing plaintext/ciphertext pairs could
    # bypass the first round entirely
    R = [P[i] ^ subkeys[i] for i in range(4)]

    # 16 Feistel rounds
    for r in range(16):
        T0 = _h(R[0], S, k)
        T1 = _h(_rol32(R[1], 8), S, k)   # ROL(R[1], 8) before h

        # PHT + subkey injection
        F0 = (T0 + T1     + subkeys[2 * r + 8]) & 0xFFFFFFFF
        F1 = (T0 + 2 * T1 + subkeys[2 * r + 9]) & 0xFFFFFFFF

        # XOR into the other half-pair with 1-bit rotations
        R[2] = _ror32(R[2] ^ F0, 1)        # XOR first, then ROR
        R[3] = _rol32(R[3], 1) ^ F1        # ROL first, then XOR

        # Swap all four words (Feistel step)
        R[0], R[1], R[2], R[3] = R[2], R[3], R[0], R[1]

    # Undo the final implicit swap
    R[0], R[1], R[2], R[3] = R[2], R[3], R[0], R[1]

    # Output whitening: XOR with K[4..7]
    C = [R[i] ^ subkeys[i + 4] for i in range(4)]
    return struct.pack("<4I", *C)


def _twofish_decrypt_block(block: bytes, subkeys: list, S: list, k: int) -> bytes:
    """
    Decrypt one 128-bit block — the exact inverse of _twofish_encrypt_block.

    INVERSION:
      Output whitening is undone first (XOR with K[4..7]).
      Rounds are processed in reverse order (15 down to 0).
      In each round, the ROR/ROL operations are swapped:
        Encryption: R[2] = ROR(R[2], 1) XOR F0
        Decryption: R[2] = ROL(R[2] XOR F0, 1)   ← inverse
      Subkeys K[2r+8] and K[2r+9] are used in the same positions —
      the Feistel structure guarantees correctness automatically.
    """
    C = list(struct.unpack("<4I", block))
    R = [C[i] ^ subkeys[i + 4] for i in range(4)]    # undo output whitening

    for r in range(15, -1, -1):                        # reverse round order
        T0 = _h(R[0], S, k)
        T1 = _h(_rol32(R[1], 8), S, k)

        F0 = (T0 + T1     + subkeys[2 * r + 8]) & 0xFFFFFFFF
        F1 = (T0 + 2 * T1 + subkeys[2 * r + 9]) & 0xFFFFFFFF

        R[2] = _rol32(R[2], 1) ^ F0          # inverse of XOR-then-ROR  →  ROL then XOR
        R[3] = _ror32(R[3] ^ F1, 1)          # inverse of ROL-then-XOR  →  XOR then ROR

        R[0], R[1], R[2], R[3] = R[2], R[3], R[0], R[1]

    R[0], R[1], R[2], R[3] = R[2], R[3], R[0], R[1]
    P = [R[i] ^ subkeys[i] for i in range(4)]         # undo input whitening
    return struct.pack("<4I", *P)


# ═══════════════════════════════════════════════════════════════
#  PADDING  (PKCS#7)
# ═══════════════════════════════════════════════════════════════

def _pad(data: bytes) -> bytes:
    """Pad to multiple of 16 bytes (Twofish block size) using PKCS#7."""
    pad_len = 16 - (len(data) % 16)     # always 1..16
    return data + bytes([pad_len] * pad_len)


def _unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding. Last byte encodes the padding length."""
    pad_len = data[-1]
    return data[:-pad_len]


# ═══════════════════════════════════════════════════════════════
#  CBC MODE
# ═══════════════════════════════════════════════════════════════

def twofish_encrypt_cbc(plaintext: bytes, key_bytes: bytes, iv: bytes = None) -> bytes:
    """
    Encrypt data using Twofish in CBC mode.

    AT-REST STORAGE ROLE:
      In the banking system, this function encrypts the JSON account store
      before writing it to accounts.enc on disk. The key used here is the
      server's long-term Twofish storage key — different from the session
      keys used by XTEA for in-transit encryption.

      This separation of keys (session key ↔ storage key) is good practice:
      compromising a session key does NOT expose the at-rest data, and vice versa.

    CBC CHAINING (same principle as XTEA-CBC):
      C[i] = Twofish_encrypt( P[i] XOR C[i-1] )
      Returns IV (16 bytes) || ciphertext.
    """
    subkeys, S, k = _key_schedule(key_bytes)
    iv     = iv or os.urandom(16)   # fresh 16-byte IV per encryption
    padded = _pad(plaintext)

    ciphertext = b""
    prev       = iv

    for i in range(0, len(padded), 16):
        # XOR plaintext block with previous ciphertext (CBC chaining)
        block = bytes(a ^ b for a, b in zip(padded[i:i+16], prev))
        enc   = _twofish_encrypt_block(block, subkeys, S, k)
        ciphertext += enc
        prev   = enc

    return iv + ciphertext


def twofish_decrypt_cbc(ciphertext_with_iv: bytes, key_bytes: bytes) -> bytes:
    """
    Decrypt data produced by twofish_encrypt_cbc.

    CBC DECRYPTION:
      P[i] = Twofish_decrypt(C[i]) XOR C[i-1]
      The IV (first 16 bytes) is extracted and used for the first block.
    """
    subkeys, S, k = _key_schedule(key_bytes)
    iv         = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]

    plaintext = b""
    prev      = iv

    for i in range(0, len(ciphertext), 16):
        enc_block = ciphertext[i:i+16]
        dec       = _twofish_decrypt_block(enc_block, subkeys, S, k)
        # XOR with previous ciphertext block to recover plaintext
        plain     = bytes(a ^ b for a, b in zip(dec, prev))
        plaintext += plain
        prev      = enc_block

    return _unpad(plaintext)


# ═══════════════════════════════════════════════════════════════
#  CONVENIENCE WRAPPERS
# ═══════════════════════════════════════════════════════════════

def encrypt_string(plaintext: str, key_bytes: bytes) -> bytes:
    return twofish_encrypt_cbc(plaintext.encode("utf-8"), key_bytes)


def decrypt_string(ciphertext: bytes, key_bytes: bytes) -> str:
    return twofish_decrypt_cbc(ciphertext, key_bytes).decode("utf-8")


# ═══════════════════════════════════════════════════════════════
#  SELF-TEST
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("── Twofish CBC self-test ─────────────────────────────")
    key = os.urandom(16)
    msg = "ACCOUNT:GB29NWBK60161331926819:BALANCE:£125,000.00:DATE:2025-06-01"
    enc = encrypt_string(msg, key)
    dec = decrypt_string(enc, key)
    print(f"  Original  : {msg}")
    print(f"  Encrypted : {enc.hex()[:64]}...")
    print(f"  Decrypted : {dec}")
    print(f"  Correct?    {'✅ YES' if msg == dec else '❌ NO'}")
    print(f"  CT size: {len(enc)} bytes  PT size: {len(msg)} bytes  "
          f"Ratio: {len(enc)/len(msg):.4f}")
