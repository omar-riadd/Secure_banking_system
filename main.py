"""
Secure Banking System — Main Entry Point
=========================================
Demonstrates the complete end-to-end encrypted banking system.

Run this file to see:
  1. CA setup and certificate issuance
  2. Bank server initialisation with Twofish at-rest encryption
  3. Client registration and certificate acquisition
  4. Full TLS-style handshake (ElGamal key exchange)
  5. Encrypted + signed transaction: balance check and fund transfer
  6. Session key rotation
  7. Performance benchmarks across all algorithms
  8. Handwritten verification demos (XTEA + ElGamal)

Usage:
    python main.py [--benchmark] [--verbose]
"""

import os
import sys
import argparse

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ca.certificate_authority  import CertificateAuthority
from network.bank_server        import BankServer
from network.bank_client        import BankClient
from symmetric.xtea             import handwritten_demo as xtea_demo
from asymmetric.elgamal         import handwritten_demo as elgamal_demo


# ─────────────────────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────────────────────

BANNER = r"""
╔══════════════════════════════════════════════════════════╗
║        🏦  SECURE BANKING SYSTEM  🏦                    ║
║   End-to-End Cryptographic Platform                      ║
║   XTEA + Twofish (Symmetric) | ElGamal (Asymmetric)     ║
║   Certificate Authority | TLS-Style Handshake            ║
╚══════════════════════════════════════════════════════════╝
"""


def section(title: str):
    print(f"\n{'═'*60}")
    print(f"  {title}")
    print(f"{'═'*60}")


# ─────────────────────────────────────────────────────────────
#  MAIN DEMO
# ─────────────────────────────────────────────────────────────

def run_demo():
    print(BANNER)

    # ── PHASE 1: Infrastructure Setup ─────────────────────────
    section("PHASE 1: Certificate Authority & Server Setup")
    ca     = CertificateAuthority(name="SecureBank-RootCA", bits=128)
    server = BankServer(ca=ca)

    # ── PHASE 2: Client Registration ──────────────────────────
    section("PHASE 2: Client Registration")
    alice  = BankClient(name="Alice", ca=ca)
    bob    = BankClient(name="Bob",   ca=ca)

    # ── PHASE 3: TLS-style Handshake ──────────────────────────
    section("PHASE 3: TLS-Style Handshake (ElGamal Key Exchange)")
    alice_ok = alice.perform_handshake(server)
    bob_ok   = bob.perform_handshake(server)

    if not alice_ok or not bob_ok:
        print("❌ Handshake failed — aborting demo.")
        return

    # ── PHASE 4: Transactions ─────────────────────────────────
    section("PHASE 4: Encrypted & Signed Transactions")

    print("\n  [Demo 1] Alice checks her balance (Account ACC-001)")
    alice.check_balance(server, "ACC-001")

    print("\n  [Demo 2] Bob checks his balance (Account ACC-002)")
    bob.check_balance(server, "ACC-002")

    print("\n  [Demo 3] Alice transfers £5,000 to Bob")
    alice.transfer(server, "ACC-001", "ACC-002", 5000.00)

    print("\n  [Demo 4] Verify updated balances after transfer")
    alice.check_balance(server, "ACC-001")
    bob.check_balance(server, "ACC-002")

    print("\n  [Demo 5] Alice attempts overdraft (should be rejected)")
    alice.transfer(server, "ACC-001", "ACC-002", 999999.00)

    # ── PHASE 5: Key Rotation ─────────────────────────────────
    section("PHASE 5: Session Key Rotation")
    server.rotate_session_key("CLIENT:Alice")

    # ── PHASE 6: Handwritten Verification ─────────────────────
    section("PHASE 6: Handwritten Verification Examples")
    print("\n  [XTEA — 2-round manual trace]")
    xtea_demo()
    print()
    print("  [ElGamal — small prime manual trace]")
    elgamal_demo()

    # ── PHASE 7: Audit Log ────────────────────────────────────
    section("PHASE 7: Server Audit Log")
    log = server.get_audit_log()
    for i, entry in enumerate(log, 1):
        print(f"  {i}. [{entry['timestamp']}] {entry['client']} "
              f"→ {entry['tx'].get('type')} → {entry['result']}")

    print(f"\n{'═'*60}")
    print("  ✅  DEMO COMPLETE — All systems operational")
    print(f"{'═'*60}\n")


# ─────────────────────────────────────────────────────────────
#  BENCHMARK RUNNER
# ─────────────────────────────────────────────────────────────

def run_benchmarks():
    section("PERFORMANCE BENCHMARKS")
    from performance.benchmarks import bench_symmetric, bench_asymmetric, print_report
    sym  = bench_symmetric()
    asym = bench_asymmetric()
    print_report(sym, asym)


# ─────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure Banking System Demo")
    parser.add_argument("--benchmark", action="store_true",
                        help="Run performance benchmarks after the demo")
    args = parser.parse_args()

    run_demo()

    if args.benchmark:
        run_benchmarks()
