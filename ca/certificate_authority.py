"""
Certificate Authority (CA) — Secure Banking System
====================================================
Simulates a trusted third party that:
  1. Issues digital certificates to bank clients and the server
  2. Signs certificates using ElGamal digital signatures
  3. Validates certificates on demand
  4. Maintains a Certificate Revocation List (CRL)

Certificate format (simplified X.509-style):
  {
    "serial"      : unique certificate ID,
    "subject"     : identity name (e.g., "BankServer", "Client:Alice"),
    "public_key"  : {"p":..., "g":..., "y":...},
    "issued_at"   : ISO timestamp,
    "expires_at"  : ISO timestamp,
    "issuer"      : "RootCA",
    "signature"   : {"r":..., "s":...}    ← CA's ElGamal signature
  }
"""

import json
import time
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asymmetric.elgamal import generate_keypair, get_public_key, sign, verify


# ─────────────────────────────────────────────────────────────
#  CERTIFICATE AUTHORITY
# ─────────────────────────────────────────────────────────────

class CertificateAuthority:
    """
    Root Certificate Authority for the Secure Banking System.
    Generates its own ElGamal keypair on initialisation.
    Issues and signs certificates for all participants.
    """

    def __init__(self, name: str = "SecureBank-RootCA", bits: int = 128):
        print(f"[CA] Initialising Certificate Authority: {name}")
        self.name       = name
        self.keypair    = generate_keypair(bits=bits)
        self.public_key = get_public_key(self.keypair)
        self._serial    = 1000
        self._issued    = {}    # serial → certificate
        self._revoked   = set() # revoked serial numbers (CRL)
        print(f"[CA] Root keypair generated. Public key (y): {hex(self.public_key['y'])[:20]}...")

    # ── ISSUE CERTIFICATE ─────────────────────────────────────

    def issue_certificate(self, subject: str, subject_public_key: dict,
                          validity_seconds: int = 86400) -> dict:
        """
        Issue a certificate to a subject (client or server).

        The certificate body is JSON-serialised and then signed with the
        CA's ElGamal private key using SHA-256 as the hash function.
        """
        self._serial += 1
        serial       = self._serial

        now      = int(time.time())
        cert_body = {
            "serial"     : serial,
            "subject"    : subject,
            "public_key" : subject_public_key,
            "issued_at"  : now,
            "expires_at" : now + validity_seconds,
            "issuer"     : self.name,
        }

        # Sign the canonical JSON representation of the cert body
        body_bytes = json.dumps(cert_body, sort_keys=True).encode("utf-8")
        r, s       = sign(body_bytes, self.keypair)

        certificate = {**cert_body, "signature": {"r": r, "s": s}}
        self._issued[serial] = certificate

        print(f"[CA] Certificate #{serial} issued to '{subject}'")
        return certificate

    # ── VALIDATE CERTIFICATE ──────────────────────────────────

    def validate_certificate(self, cert: dict) -> bool:
        """
        Validate a certificate:
          1. Check it was issued by this CA
          2. Check it has not expired
          3. Check it is not revoked
          4. Verify the CA's signature
        """
        serial = cert.get("serial")

        # Issuer check
        if cert.get("issuer") != self.name:
            print(f"[CA] ❌ Unknown issuer: {cert.get('issuer')}")
            return False

        # Expiry check
        if int(time.time()) > cert.get("expires_at", 0):
            print(f"[CA] ❌ Certificate #{serial} has expired.")
            return False

        # Revocation check
        if serial in self._revoked:
            print(f"[CA] ❌ Certificate #{serial} has been REVOKED.")
            return False

        # Signature verification
        sig        = cert.get("signature", {})
        r, s       = sig.get("r"), sig.get("s")
        body       = {k: v for k, v in cert.items() if k != "signature"}
        body_bytes = json.dumps(body, sort_keys=True).encode("utf-8")

        if not verify(body_bytes, r, s, self.public_key):
            print(f"[CA] ❌ Signature verification FAILED for cert #{serial}")
            return False

        print(f"[CA] ✅ Certificate #{serial} for '{cert['subject']}' is VALID")
        return True

    # ── REVOKE CERTIFICATE ────────────────────────────────────

    def revoke_certificate(self, serial: int):
        """Add a certificate serial to the CRL (Certificate Revocation List)."""
        self._revoked.add(serial)
        print(f"[CA] ⚠️  Certificate #{serial} has been REVOKED (added to CRL)")

    # ── GET CRL ───────────────────────────────────────────────

    def get_crl(self) -> list[int]:
        """Return the Certificate Revocation List."""
        return list(self._revoked)

    # ── SERIALISE / DESERIALISE CERTIFICATE ───────────────────

    @staticmethod
    def cert_to_json(cert: dict) -> str:
        return json.dumps(cert)

    @staticmethod
    def cert_from_json(data: str) -> dict:
        return json.loads(data)


# ─────────────────────────────────────────────────────────────
#  SELF-TEST
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n══════════════════════════════════════════════════════")
    print("  CERTIFICATE AUTHORITY DEMO")
    print("══════════════════════════════════════════════════════\n")

    ca = CertificateAuthority(bits=128)

    # Bank server gets a certificate
    server_keys = generate_keypair(bits=128)
    server_cert = ca.issue_certificate("BankServer-Primary", get_public_key(server_keys))

    # Client Alice gets a certificate
    alice_keys  = generate_keypair(bits=128)
    alice_cert  = ca.issue_certificate("Client:Alice", get_public_key(alice_keys))

    print()

    # Validate both
    ca.validate_certificate(server_cert)
    ca.validate_certificate(alice_cert)

    # Revoke Alice's cert
    print()
    ca.revoke_certificate(alice_cert["serial"])
    ca.validate_certificate(alice_cert)   # Should fail now

    # Tamper test
    print()
    tampered = {**server_cert, "subject": "HACKER"}
    ca.validate_certificate(tampered)     # Should fail — signature won't match
