"""
File Encryptor — Secure Banking System
=======================================
Banking Use Case: Protects documents and transaction logs stored on disk.

Supports two encryption modes:
  - XTEA  : Fast, lightweight. Used for session tokens and small files.
  - Twofish: Stronger, banking-grade. Used for account records and logs.

Usage:
    python file_encryptor.py encrypt <input_file> <output_file> --algo [xtea|twofish]
    python file_encryptor.py decrypt <input_file> <output_file> --algo [xtea|twofish]
"""

import os
import sys
import time
import json
import hashlib
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from symmetric.xtea    import xtea_encrypt_cbc, xtea_decrypt_cbc
from symmetric.twofish import twofish_encrypt_cbc, twofish_decrypt_cbc


# ─────────────────────────────────────────────────────────────
#  KEY DERIVATION  (PBKDF2-like — using SHA-256 + iterations)
# ─────────────────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes, key_len: int = 16, iterations: int = 10000) -> bytes:
    """
    Derive a symmetric key from a password using iterated SHA-256 hashing.
    This is a simplified PBKDF2 implemented without hashlib.pbkdf2_hmac.
    Only uses: hashlib.sha256 (basic hash, not a crypto library).
    """
    dk = (password.encode("utf-8") + salt)
    for _ in range(iterations):
        dk = hashlib.sha256(dk).digest()
    return dk[:key_len]


# ─────────────────────────────────────────────────────────────
#  FILE ENCRYPTION / DECRYPTION
# ─────────────────────────────────────────────────────────────

def encrypt_file(input_path: str, output_path: str, password: str, algo: str = "twofish") -> dict:
    """
    Encrypt a file and write the result to output_path.
    The output file includes a JSON header with salt and metadata,
    followed by the raw ciphertext.

    Returns a performance report dict.
    """
    with open(input_path, "rb") as f:
        plaintext = f.read()

    salt       = os.urandom(16)
    key_len    = 16                       # 128-bit key for both XTEA and Twofish
    key        = _derive_key(password, salt, key_len)

    t_start    = time.perf_counter()

    if algo == "xtea":
        ciphertext = xtea_encrypt_cbc(plaintext, key)
    elif algo == "twofish":
        ciphertext = twofish_encrypt_cbc(plaintext, key)
    else:
        raise ValueError(f"Unknown algorithm: {algo}. Choose 'xtea' or 'twofish'.")

    t_end      = time.perf_counter()
    elapsed_ms = (t_end - t_start) * 1000

    # Build file header
    header = {
        "algorithm" : algo,
        "salt_hex"  : salt.hex(),
        "plaintext_size" : len(plaintext),
        "ciphertext_size": len(ciphertext),
        "ratio"     : round(len(ciphertext) / len(plaintext), 4),
    }
    header_bytes = json.dumps(header).encode("utf-8")

    # Write: 4-byte header-length prefix | header JSON | ciphertext
    with open(output_path, "wb") as f:
        f.write(len(header_bytes).to_bytes(4, "big"))
        f.write(header_bytes)
        f.write(ciphertext)

    return {
        "algorithm"      : algo,
        "plaintext_size" : len(plaintext),
        "ciphertext_size": len(ciphertext),
        "ratio"          : header["ratio"],
        "encrypt_ms"     : round(elapsed_ms, 4),
    }


def decrypt_file(input_path: str, output_path: str, password: str) -> dict:
    """
    Decrypt a file previously encrypted with encrypt_file.
    Reads the header to determine algorithm and salt, then decrypts.
    """
    with open(input_path, "rb") as f:
        header_len   = int.from_bytes(f.read(4), "big")
        header       = json.loads(f.read(header_len).decode("utf-8"))
        ciphertext   = f.read()

    algo           = header["algorithm"]
    salt           = bytes.fromhex(header["salt_hex"])
    key            = _derive_key(password, salt, 16)

    t_start = time.perf_counter()

    if algo == "xtea":
        plaintext = xtea_decrypt_cbc(ciphertext, key)
    elif algo == "twofish":
        plaintext = twofish_decrypt_cbc(ciphertext, key)
    else:
        raise ValueError(f"Unknown algorithm in file header: {algo}")

    t_end      = time.perf_counter()
    elapsed_ms = (t_end - t_start) * 1000

    with open(output_path, "wb") as f:
        f.write(plaintext)

    return {
        "algorithm"   : algo,
        "decrypt_ms"  : round(elapsed_ms, 4),
        "output_size" : len(plaintext),
    }


# ─────────────────────────────────────────────────────────────
#  CLI INTERFACE
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Secure Banking File Encryptor (XTEA / Twofish)"
    )
    parser.add_argument("action",      choices=["encrypt", "decrypt"])
    parser.add_argument("input_file")
    parser.add_argument("output_file")
    parser.add_argument("--algo",      default="twofish", choices=["xtea", "twofish"])
    parser.add_argument("--password",  default="SecureBankPass123!")
    args = parser.parse_args()

    if args.action == "encrypt":
        report = encrypt_file(args.input_file, args.output_file, args.password, args.algo)
        print(f"\n  ✅ Encrypted '{args.input_file}' → '{args.output_file}'")
        print(f"  Algorithm       : {report['algorithm'].upper()}")
        print(f"  Plaintext size  : {report['plaintext_size']} bytes")
        print(f"  Ciphertext size : {report['ciphertext_size']} bytes")
        print(f"  Expansion ratio : {report['ratio']}")
        print(f"  Encrypt time    : {report['encrypt_ms']} ms\n")
    else:
        report = decrypt_file(args.input_file, args.output_file, args.password)
        print(f"\n  ✅ Decrypted '{args.input_file}' → '{args.output_file}'")
        print(f"  Algorithm       : {report['algorithm'].upper()}")
        print(f"  Output size     : {report['output_size']} bytes")
        print(f"  Decrypt time    : {report['decrypt_ms']} ms\n")


if __name__ == "__main__":
    main()
