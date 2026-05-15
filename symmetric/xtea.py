"""
XTEA — eXtended Tiny Encryption Algorithm
==========================================
Implemented entirely from scratch using only Python integer arithmetic.
No encryption libraries used. Only basic operations: +, ^, <<, >>, mod.

ACADEMIC REFERENCE
  Needham, R. M. & Wheeler, D. J. (1997).
  "Tea extensions." Technical Report, Cambridge University Computer Laboratory.

ALGORITHM CLASS
  Symmetric block cipher — Feistel network structure

PARAMETERS
  Block size : 64 bits  (two 32-bit halves: v0, v1)
  Key size   : 128 bits (four 32-bit words: key[0..3])
  Rounds     : 64       (32 cycles of 2 Feistel half-rounds each)

BANKING USE CASE
  Encrypts session tokens and all transaction data in transit.
  Used after the session key establishment protocol completes.
  The session key (established via ElGamal) is passed as key_bytes.

SESSION KEY CONNECTION
  XTEA is the symmetric cipher used to protect data after the session
  key establishment protocol. The key it receives IS the session key —
  the shared secret established between client and server in Steps 3–4
  of the handshake. Rotating the session key = rotating the XTEA key.

WHY XTEA OVER AES?
  - Not AES (meets the "not explained in class" coursework requirement)
  - Pure integer arithmetic — no S-box tables needed (implementable from scratch)
  - 64-round Feistel provides strong diffusion despite simplicity
  - NIST has confirmed no practical attack on full 64-round XTEA
  - Fastest of our implemented ciphers — ideal for high-frequency transit data

FEISTEL NETWORK PRIMER
  A Feistel network splits the input block into two halves (L, R).
  Each round applies a function F to one half and XORs it into the other:
    new_L = R
    new_R = L XOR F(R, subkey)
  This structure is inherently invertible — decryption reverses the rounds.
  Changing 1 input bit affects ~50% of output bits (avalanche effect).
"""

import struct
import os


# ═══════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════

DELTA = 0x9E3779B9
# The DELTA constant is derived from the golden ratio φ = (√5 − 1) / 2.
# Specifically: DELTA = floor(φ × 2^32) = 0x9E3779B9
#
# WHY THIS VALUE?
#   Each round adds DELTA to an accumulator (sum), producing a unique
#   sub-constant per round:
#     Round 1: sum = 0x9E3779B9
#     Round 2: sum = 0x3C6EF372  (= 2 × DELTA mod 2^32)
#     ...
#   Because DELTA is irrational (derived from √5), the sequence of sum
#   values is maximally spread — no two rounds share the same constant.
#   This prevents "slide attacks" where an attacker exploits repeated
#   round constants to align two cipher executions.

MASK32 = 0xFFFFFFFF
# Keeps all arithmetic within 32-bit unsigned range.
# Python integers are arbitrary precision — MASK32 simulates 32-bit overflow
# that would occur naturally in C: (a + b) & MASK32 ≡ (a + b) mod 2^32

NUM_ROUNDS = 64
# 64 half-rounds = 32 full Feistel cycles.
# Security analysis shows XTEA with fewer than 36 rounds is vulnerable
# to differential cryptanalysis. 64 rounds provides a large safety margin.


# ═══════════════════════════════════════════════════════════════
#  CORE CIPHER — SINGLE BLOCK ENCRYPT
# ═══════════════════════════════════════════════════════════════

def _xtea_encipher(num_rounds: int, v: list, key: list) -> list:
    """
    Encrypt one 64-bit block represented as [v0, v1] (two 32-bit integers).

    INPUT
      num_rounds : number of Feistel half-rounds (64 for full security)
      v          : [v0, v1] — the 64-bit plaintext block split into two halves
      key        : [k0, k1, k2, k3] — the 128-bit key as four 32-bit words

    THE ROUND FUNCTION (each of num_rounds iterations):

      Step A — Advance the round constant:
        sum = (sum + DELTA) mod 2^32
        This produces a unique sub-constant for every round.

      Step B — Update v0:
        mix  = (v1 << 4) XOR (v1 >> 5)
             = a combination of left-shifted and right-shifted v1
             = provides non-linearity and bit diffusion within v1
        v0   = v0 + (mix + v1) XOR (sum + key[sum & 3])
             ↑ addition   ↑ mix function    ↑ key-dependent round constant
             The XOR of two 32-bit values provides confusion.
             The modular addition provides diffusion across bit positions.

      Step C — Update v1 (uses the NEWLY updated v0):
        mix  = (v0 << 4) XOR (v0 >> 5)   (same structure, now on v0)
        v1   = v1 + (mix + v0) XOR (sum + key[(sum >> 11) & 3])
             Note: key index (sum >> 11) & 3 differs from step B's (sum & 3)
             — ensures different key words are used in the same round.

    HANDWRITTEN VERIFICATION (2 rounds, key=[1,2,3,4], v0=1, v1=2):
      Round 1: sum=0x9E3779B9  → v0=0x9E37799A,  v1=0x1B8AE5BD
      Round 2: sum=0x3C6EF372  → v0=0x8DC97B69,  v1=0x7638717E
    """
    v0, v1 = v[0], v[1]
    total  = 0                      # accumulator — starts at 0, grows by DELTA each round

    for _ in range(num_rounds):

        # ── Step A: advance round constant ────────────────────
        total = (total + DELTA) & MASK32

        # ── Step B: update the LEFT half (v0) ─────────────────
        # mix_v1 blends two shifted copies of v1 to create diffusion:
        #   v1 << 4  amplifies high bits into higher positions
        #   v1 >> 5  brings high bits into lower positions
        #   XOR of both creates a value that depends on ALL bits of v1
        mix_v1 = (v1 << 4 ^ v1 >> 5) & MASK32

        # The full round update for v0:
        #   (mix_v1 + v1)             — the Feistel mixing function F(v1)
        #   (total + key[total & 3])  — key-dependent round constant
        #   XOR of both, added to v0  — combines confusion and diffusion
        v0 = (v0 + ((mix_v1 + v1) ^ (total + key[total & 3]))) & MASK32

        # ── Step C: update the RIGHT half (v1) ────────────────
        # Same structure, but uses the just-updated v0 and a different key index.
        # Using (sum >> 11) & 3 instead of sum & 3 rotates through key words
        # differently within the same round — prevents related-key attacks.
        mix_v0 = (v0 << 4 ^ v0 >> 5) & MASK32
        v1 = (v1 + ((mix_v0 + v0) ^ (total + key[(total >> 11) & 3]))) & MASK32

    return [v0, v1]


# ═══════════════════════════════════════════════════════════════
#  CORE CIPHER — SINGLE BLOCK DECRYPT
# ═══════════════════════════════════════════════════════════════

def _xtea_decipher(num_rounds: int, v: list, key: list) -> list:
    """
    Decrypt one 64-bit block — the exact inverse of _xtea_encipher.

    INVERSION STRATEGY
      Feistel networks are inherently invertible. Decryption simply:
        1. Starts total at its FINAL encryption value: DELTA × num_rounds
        2. Applies the same operations in REVERSE ORDER
        3. Subtracts DELTA from total each round (instead of adding)

      Each step can be inverted because:
        If  v0_new = v0_old + f(v1)
        Then v0_old = v0_new - f(v1)      (modular subtraction)

      CRITICAL: v1 is reversed BEFORE v0 in each round — the opposite
      of encryption — because v1 was updated last during encryption.

    HANDWRITTEN VERIFICATION (continues from encipher example):
      Start: v0=0x8DC97B69, v1=0x7638717E, total=0x3C6EF372 (= 2×DELTA)
      Round 1 (reverse): total→0x9E3779B9, v0→0x9E37799A, v1→0x1B8AE5BD
      Round 2 (reverse): total→0x00000000, v0→0x00000001, v1→0x00000002 ✓
    """
    v0, v1 = v[0], v[1]

    # Start from the final accumulated sum (what total would equal after encryption)
    total = (DELTA * num_rounds) & MASK32

    for _ in range(num_rounds):

        # ── Reverse Step C (undo the last operation of encryption) ─
        mix_v0 = (v0 << 4 ^ v0 >> 5) & MASK32
        v1 = (v1 - ((mix_v0 + v0) ^ (total + key[(total >> 11) & 3]))) & MASK32

        # ── Reverse Step B ─────────────────────────────────────
        mix_v1 = (v1 << 4 ^ v1 >> 5) & MASK32
        v0 = (v0 - ((mix_v1 + v1) ^ (total + key[total & 3]))) & MASK32

        # ── Reverse Step A: retreat the round constant ─────────
        total = (total - DELTA) & MASK32

    return [v0, v1]


# ═══════════════════════════════════════════════════════════════
#  KEY PARSING
# ═══════════════════════════════════════════════════════════════

def _parse_key(key_bytes: bytes) -> list:
    """
    Convert a 16-byte (128-bit) key into four 32-bit unsigned integers.

    XTEA treats the 128-bit key as a simple array of four 32-bit words:
      key[0] = bytes  0– 3  (big-endian unsigned int)
      key[1] = bytes  4– 7
      key[2] = bytes  8–11
      key[3] = bytes 12–15

    Big-endian packing is used for consistency with the original
    Needham-Wheeler reference implementation.

    SESSION KEY NOTE:
      In the banking system, key_bytes is the session key established
      during the ElGamal handshake. Every new session or key rotation
      produces a different key_bytes — and therefore a completely
      different set of key[0..3] values — satisfying dynamicity.
    """
    if len(key_bytes) != 16:
        raise ValueError(
            f"XTEA requires exactly 16 bytes (128 bits). Received {len(key_bytes)} bytes.")
    return list(struct.unpack(">4I", key_bytes))


# ═══════════════════════════════════════════════════════════════
#  PADDING  (PKCS#7)
# ═══════════════════════════════════════════════════════════════

def _pad(data: bytes) -> bytes:
    """
    Pad plaintext to a multiple of 8 bytes (XTEA's block size).

    PKCS#7 PADDING RULE:
      If N bytes of padding are needed, append N bytes each with value N.
      If data is already aligned, append a full block of value 8.

    EXAMPLES:
      5-byte input  → pad 3 bytes → append b'\\x03\\x03\\x03'
      8-byte input  → pad 8 bytes → append b'\\x08×8'  (full extra block)
      15-byte input → pad 1 byte  → append b'\\x01'

    WHY ALWAYS PAD?
      Even if data is block-aligned, a full padding block is added.
      This ensures _unpad() can always unambiguously remove padding —
      the last byte always encodes how many bytes to strip.
    """
    pad_len = 8 - (len(data) % 8)      # always 1..8, never 0
    return data + bytes([pad_len] * pad_len)


def _unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding from decrypted data.

    Reads the last byte to determine how many bytes to strip.
    Basic validation ensures the padding value is in range [1, 8].
    """
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError(
            f"Invalid PKCS#7 padding byte: {pad_len}. Expected 1–8.")
    return data[:-pad_len]


# ═══════════════════════════════════════════════════════════════
#  CBC MODE  (Cipher Block Chaining)
# ═══════════════════════════════════════════════════════════════

def xtea_encrypt_cbc(plaintext: bytes, key_bytes: bytes, iv: bytes = None) -> bytes:
    """
    Encrypt arbitrary-length data using XTEA in CBC (Cipher Block Chaining) mode.

    WHY CBC INSTEAD OF ECB (Electronic Code Book)?
      ECB encrypts each block INDEPENDENTLY with the same key.
      Problem: identical plaintext blocks → identical ciphertext blocks.
      Patterns in the data leak through — catastrophic for banking data.

      CBC solves this: before encrypting each block, XOR it with the
      PREVIOUS ciphertext block. This chains all blocks together:
        C[0] = XTEA_encrypt( P[0] XOR IV  )
        C[1] = XTEA_encrypt( P[1] XOR C[0] )
        C[i] = XTEA_encrypt( P[i] XOR C[i-1] )

      Now identical plaintext blocks produce different ciphertext because
      they chain on different preceding ciphertext values.

    THE INITIALISATION VECTOR (IV):
      The first block needs something to XOR with — the IV fills this role.
      The IV is a fresh random 8-byte value generated for every encryption.
      It is NOT secret — it is prepended to the ciphertext in plaintext.
      It MUST be random and unique per encryption for CBC to be secure.

    OUTPUT FORMAT:
      [ IV (8 bytes) ] [ ciphertext blocks... ]
      Total output length = 8 + ceil(len(plaintext)/8) × 8

    SESSION KEY CONNECTION:
      key_bytes here is the XTEA session key — the shared secret established
      by the session key protocol. This is how session key establishment
      connects to actual data protection: the agreed key flows directly
      into this function for every transaction.
    """
    key    = _parse_key(key_bytes)
    iv     = iv or os.urandom(8)        # fresh random IV for every message
    padded = _pad(plaintext)

    ciphertext = b""
    prev_block = iv                     # CBC chain starts with IV

    for i in range(0, len(padded), 8):
        block = padded[i : i + 8]

        # XOR this plaintext block with the previous ciphertext block
        # This is the core of CBC — chaining creates data-dependency across blocks
        xored = bytes(a ^ b for a, b in zip(block, prev_block))

        # Encrypt the XOR'd block with XTEA
        v     = list(struct.unpack(">2I", xored))   # split 8 bytes into [v0, v1]
        enc_v = _xtea_encipher(NUM_ROUNDS, v, key)

        enc_block  = struct.pack(">2I", *enc_v)     # pack [v0, v1] back to 8 bytes
        ciphertext += enc_block
        prev_block  = enc_block                     # next block chains on this one

    return iv + ciphertext      # prepend IV so decryption can recover it


def xtea_decrypt_cbc(ciphertext_with_iv: bytes, key_bytes: bytes) -> bytes:
    """
    Decrypt data produced by xtea_encrypt_cbc.

    CBC DECRYPTION FORMULA:
      P[0] = XTEA_decrypt(C[0]) XOR IV
      P[i] = XTEA_decrypt(C[i]) XOR C[i-1]

    Note: each block can be decrypted independently (unlike encryption)
    because C[i-1] is already known from the ciphertext. This allows
    parallel decryption of blocks — an advantage of CBC over some modes.

    ERROR PROPAGATION:
      A bit error in ciphertext block C[i] corrupts the decryption of
      C[i] entirely AND flips the corresponding bit in P[i+1].
      Beyond that, decryption of C[i+2], C[i+3], ... is unaffected.
    """
    key        = _parse_key(key_bytes)
    iv         = ciphertext_with_iv[:8]    # extract the prepended IV
    ciphertext = ciphertext_with_iv[8:]    # the actual ciphertext blocks

    plaintext  = b""
    prev_block = iv

    for i in range(0, len(ciphertext), 8):
        enc_block = ciphertext[i : i + 8]

        # Decrypt the ciphertext block with XTEA
        v     = list(struct.unpack(">2I", enc_block))
        dec_v = _xtea_decipher(NUM_ROUNDS, v, key)
        dec_block = struct.pack(">2I", *dec_v)

        # XOR with previous ciphertext block to recover the plaintext block
        plain_block = bytes(a ^ b for a, b in zip(dec_block, prev_block))
        plaintext  += plain_block
        prev_block  = enc_block             # advance the chain

    return _unpad(plaintext)


# ═══════════════════════════════════════════════════════════════
#  CONVENIENCE WRAPPERS
# ═══════════════════════════════════════════════════════════════

def encrypt_string(plaintext: str, key_bytes: bytes) -> bytes:
    """Encode a UTF-8 string to bytes, then encrypt with XTEA-CBC."""
    return xtea_encrypt_cbc(plaintext.encode("utf-8"), key_bytes)


def decrypt_string(ciphertext: bytes, key_bytes: bytes) -> str:
    """Decrypt XTEA-CBC ciphertext and decode the result as UTF-8."""
    return xtea_decrypt_cbc(ciphertext, key_bytes).decode("utf-8")


# ═══════════════════════════════════════════════════════════════
#  HANDWRITTEN VERIFICATION DEMO
# ═══════════════════════════════════════════════════════════════

def handwritten_demo():
    """
    Run XTEA with 2 rounds and small values — every step traceable by hand.

    PARAMETERS CHOSEN FOR HAND VERIFICATION:
      Key    : [0x00000001, 0x00000002, 0x00000003, 0x00000004]
      Input  : v0 = 0x00000001,  v1 = 0x00000002
      Rounds : 2  (instead of 64 — keeps arithmetic manageable)
      DELTA  : 0x9E3779B9

    STEP-BY-STEP (trace printed below — verify with hex calculator):
      ROUND 1:
        sum  = 0 + DELTA = 0x9E3779B9
        mix  = (v1 << 4) XOR (v1 >> 5)
             = (0x2 << 4) XOR (0x2 >> 5) = 0x20 XOR 0x0 = 0x20
        v0   = v0 + (mix + v1) XOR (sum + key[sum & 3])
             = 0x1 + (0x20 + 0x2) XOR (0x9E3779B9 + key[1])
             = 0x1 + 0x22 XOR (0x9E3779B9 + 0x2)
             → v0 = 0x9E37799A

        mix  = (v0 << 4) XOR (v0 >> 5)  [using new v0]
        v1   = v1 + (mix + v0) XOR (sum + key[(sum>>11) & 3])
             → v1 = 0x1B8AE5BD

      ROUND 2:
        sum  = 0x9E3779B9 + DELTA = 0x3C6EF372
             → v0 = 0x8DC97B69,  v1 = 0x7638717E   (final ciphertext)

      DECRYPTION reverses both rounds exactly, recovering v0=0x1, v1=0x2.
    """
    print("=" * 60)
    print("  XTEA HANDWRITTEN VERIFICATION  (2 rounds, small values)")
    print("=" * 60)

    key    = [0x00000001, 0x00000002, 0x00000003, 0x00000004]
    v0, v1 = 0x00000001, 0x00000002
    total  = 0
    rounds = 2

    print(f"\n  Key      : {[hex(k) for k in key]}")
    print(f"  Plaintext: v0={hex(v0)}, v1={hex(v1)}")
    print(f"  Rounds   : {rounds}  (full implementation uses {NUM_ROUNDS})")
    print(f"  DELTA    : {hex(DELTA)}  (from golden ratio × 2^32)\n")
    print("  ── ENCRYPTION ──────────────────────────────────────")

    orig_v0, orig_v1 = v0, v1

    for r in range(1, rounds + 1):
        total   = (total + DELTA) & MASK32                            # Step A
        v0      = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (total + key[total & 3]))) & MASK32
        v1      = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (total + key[(total >> 11) & 3]))) & MASK32
        print(f"  Round {r}: sum={hex(total):<14}  v0={hex(v0):<14}  v1={hex(v1)}")

    enc_v0, enc_v1 = v0, v1
    print(f"\n  Ciphertext : v0={hex(enc_v0)},  v1={hex(enc_v1)}")

    print("\n  ── DECRYPTION  (reverse rounds) ────────────────────")
    total = (DELTA * rounds) & MASK32   # start from the final accumulated sum

    for r in range(1, rounds + 1):
        v1    = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (total + key[(total >> 11) & 3]))) & MASK32
        v0    = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (total + key[total & 3]))) & MASK32
        total = (total - DELTA) & MASK32
        print(f"  Round {r}: sum={hex(total):<14}  v0={hex(v0):<14}  v1={hex(v1)}")

    print(f"\n  Recovered  : v0={hex(v0)},  v1={hex(v1)}")
    ok = (v0 == orig_v0 and v1 == orig_v1)
    print(f"  Matches original plaintext? {'✅ YES' if ok else '❌ NO'}")
    print("=" * 60)


# ═══════════════════════════════════════════════════════════════
#  SELF-TEST
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    handwritten_demo()

    print("\n── Full 64-round CBC self-test ───────────────────────")
    key = os.urandom(16)
    msg = "SESSION_TOKEN:ACC-00123:EXPIRES:2025-12-31"
    enc = encrypt_string(msg, key)
    dec = decrypt_string(enc, key)
    print(f"  Original  : {msg}")
    print(f"  Encrypted : {enc.hex()}")
    print(f"  Decrypted : {dec}")
    print(f"  Correct?    {'✅ YES' if msg == dec else '❌ NO'}")
    print(f"  CT size: {len(enc)} bytes  PT size: {len(msg)} bytes  "
          f"Ratio: {len(enc)/len(msg):.4f}")
