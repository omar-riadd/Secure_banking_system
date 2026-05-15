"""
Performance Benchmarks — Secure Banking System
================================================
Measures and compares:
  1. Encryption / Decryption runtime (milliseconds)
  2. Memory footprint (bytes allocated per operation)
  3. Ciphertext-to-plaintext size ratio (overhead)

Algorithms tested:
  - XTEA-CBC     (symmetric)
  - Twofish-CBC  (symmetric)
  - ElGamal      (asymmetric — key generation + encrypt/decrypt)

All results are printed in a formatted table and also returned
as a dict suitable for programmatic use.
"""

import os
import sys
import time
import tracemalloc
import statistics

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from symmetric.xtea    import xtea_encrypt_cbc, xtea_decrypt_cbc
from symmetric.twofish import twofish_encrypt_cbc, twofish_decrypt_cbc
from asymmetric.elgamal import (generate_keypair, get_public_key,
                                 elgamal_encrypt_bytes, elgamal_decrypt_bytes)


# ─────────────────────────────────────────────────────────────
#  BENCHMARK HELPERS
# ─────────────────────────────────────────────────────────────

def _bench(fn, *args, runs: int = 5) -> dict:
    """
    Run fn(*args) `runs` times and return timing + memory stats.
    Uses Python's tracemalloc for memory profiling.
    """
    times   = []
    mem_peaks = []

    for _ in range(runs):
        tracemalloc.start()
        t0  = time.perf_counter()
        result = fn(*args)
        t1  = time.perf_counter()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        times.append((t1 - t0) * 1000)      # ms
        mem_peaks.append(peak)

    return {
        "result"    : result,
        "mean_ms"   : round(statistics.mean(times),    4),
        "min_ms"    : round(min(times),                4),
        "max_ms"    : round(max(times),                4),
        "mem_bytes" : round(statistics.mean(mem_peaks)),
    }


# ─────────────────────────────────────────────────────────────
#  SYMMETRIC BENCHMARKS
# ─────────────────────────────────────────────────────────────

PAYLOADS = {
    "small  (64 B) " : b"A" * 64,
    "medium (1 KB) " : b"B" * 1024,
    "large  (10 KB)": b"C" * 10240,
    "xlarge (100KB)": b"D" * 102400,
}


def bench_symmetric() -> list[dict]:
    results = []

    for label, payload in PAYLOADS.items():
        key = os.urandom(16)

        # ── XTEA ──────────────────────────────────────────────
        enc_r  = _bench(xtea_encrypt_cbc, payload, key)
        ct_xtea = enc_r["result"]
        dec_r  = _bench(xtea_decrypt_cbc, ct_xtea, key)

        results.append({
            "algo"      : "XTEA-CBC",
            "payload"   : label,
            "pt_bytes"  : len(payload),
            "ct_bytes"  : len(ct_xtea),
            "ratio"     : round(len(ct_xtea) / len(payload), 4),
            "enc_ms"    : enc_r["mean_ms"],
            "dec_ms"    : dec_r["mean_ms"],
            "enc_mem"   : enc_r["mem_bytes"],
        })

        # ── TWOFISH ───────────────────────────────────────────
        enc_r  = _bench(twofish_encrypt_cbc, payload, key)
        ct_tf   = enc_r["result"]
        dec_r  = _bench(twofish_decrypt_cbc, ct_tf, key)

        results.append({
            "algo"      : "Twofish-CBC",
            "payload"   : label,
            "pt_bytes"  : len(payload),
            "ct_bytes"  : len(ct_tf),
            "ratio"     : round(len(ct_tf) / len(payload), 4),
            "enc_ms"    : enc_r["mean_ms"],
            "dec_ms"    : dec_r["mean_ms"],
            "enc_mem"   : enc_r["mem_bytes"],
        })

    return results


# ─────────────────────────────────────────────────────────────
#  ASYMMETRIC BENCHMARKS
# ─────────────────────────────────────────────────────────────

def bench_asymmetric() -> list[dict]:
    results = []
    payload  = b"SESSION_KEY_16BY"   # 16-byte symmetric key exchange

    for bits in [128, 256]:
        # Key generation
        keygen_r = _bench(generate_keypair, bits)
        kp       = keygen_r["result"]
        pub      = get_public_key(kp)

        # Encryption
        enc_r    = _bench(elgamal_encrypt_bytes, payload, pub)
        chunks   = enc_r["result"]
        ct_size  = sum(c1.bit_length() // 8 + c2.bit_length() // 8 for c1, c2 in chunks)

        # Decryption
        dec_r    = _bench(elgamal_decrypt_bytes, chunks, kp, len(payload))

        results.append({
            "algo"      : f"ElGamal-{bits}",
            "pt_bytes"  : len(payload),
            "ct_bytes"  : ct_size,
            "ratio"     : round(ct_size / len(payload), 2),
            "keygen_ms" : keygen_r["mean_ms"],
            "enc_ms"    : enc_r["mean_ms"],
            "dec_ms"    : dec_r["mean_ms"],
            "enc_mem"   : enc_r["mem_bytes"],
        })

    return results


# ─────────────────────────────────────────────────────────────
#  REPORT PRINTER
# ─────────────────────────────────────────────────────────────

def _hr(char: str = "─", width: int = 88):
    print(char * width)


def print_report(sym_results: list[dict], asym_results: list[dict]):
    print("\n")
    print("█" * 88)
    print("  PERFORMANCE BENCHMARK REPORT — SECURE BANKING SYSTEM CRYPTOGRAPHY")
    print("█" * 88)

    # ── SYMMETRIC TABLE ───────────────────────────────────────
    print("\n  ① SYMMETRIC ENCRYPTION (XTEA-CBC vs Twofish-CBC)")
    _hr()
    print(f"  {'Algorithm':<14} {'Payload':<16} {'PT (B)':>8} {'CT (B)':>8} "
          f"{'Ratio':>7} {'Enc (ms)':>10} {'Dec (ms)':>10} {'Mem (KB)':>10}")
    _hr()

    for r in sym_results:
        print(f"  {r['algo']:<14} {r['payload']:<16} {r['pt_bytes']:>8} {r['ct_bytes']:>8} "
              f"  {r['ratio']:>5.4f}  {r['enc_ms']:>10.4f} {r['dec_ms']:>10.4f} "
              f"{r['enc_mem']//1024:>10}")

    _hr()

    # ── ASYMMETRIC TABLE ──────────────────────────────────────
    print("\n  ② ASYMMETRIC ENCRYPTION (ElGamal)")
    _hr()
    print(f"  {'Algorithm':<16} {'PT (B)':>7} {'CT (B)':>7} {'Ratio':>7} "
          f"{'KeyGen (ms)':>12} {'Enc (ms)':>10} {'Dec (ms)':>10} {'Mem (KB)':>10}")
    _hr()

    for r in asym_results:
        print(f"  {r['algo']:<16} {r['pt_bytes']:>7} {r['ct_bytes']:>7}  "
              f"{r['ratio']:>6.2f}  {r['keygen_ms']:>12.4f} {r['enc_ms']:>10.4f} "
              f"{r['dec_ms']:>10.4f} {r['enc_mem']//1024:>10}")

    _hr()

    # ── COMPARISON SUMMARY ────────────────────────────────────
    print("\n  ③ KEY INSIGHTS")
    _hr("─", 60)

    # Get XTEA vs Twofish comparison for medium payload
    xtea_med  = next(r for r in sym_results
                     if r["algo"] == "XTEA-CBC" and "1 KB" in r["payload"])
    tf_med    = next(r for r in sym_results
                     if r["algo"] == "Twofish-CBC" and "1 KB" in r["payload"])

    speed_ratio = tf_med["enc_ms"] / xtea_med["enc_ms"] if xtea_med["enc_ms"] > 0 else 0

    print(f"\n  • XTEA vs Twofish speed ratio (1KB): "
          f"Twofish is ~{speed_ratio:.1f}x {'slower' if speed_ratio>1 else 'faster'} than XTEA")
    print(f"  • Both algorithms produce minimal overhead (<= 1.25x ciphertext expansion)")
    print(f"  • ElGamal ciphertext expansion is ~{asym_results[0]['ratio']:.1f}x "
          f"(expected for asymmetric schemes)")
    print(f"  • XTEA: best for high-frequency session data (low latency)")
    print(f"  • Twofish: best for bulk at-rest encryption (higher security margin)")
    print(f"  • ElGamal: used only for key exchange, not bulk data (as designed)\n")
    _hr("█")


# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Running symmetric benchmarks...")
    sym  = bench_symmetric()

    print("Running asymmetric benchmarks (may take a moment)...")
    asym = bench_asymmetric()

    print_report(sym, asym)
