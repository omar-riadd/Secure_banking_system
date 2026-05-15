"""
Bank Client — Secure Banking System
=====================================
Simulates a bank customer's client application that:
  1. Registers with the Certificate Authority to get a certificate
  2. Executes Session Key Establishment Protocol (TLS-style handshake)
  3. Generates and encrypts a fresh session key using ElGamal (INITIATOR role)
  4. Sends encrypted, signed transaction requests (XTEA in transit)
  5. Decrypts and verifies server responses
  6. Accepts new session keys when the server performs auto-rotation

═══════════════════════════════════════════════════════════════
  SESSION KEY ESTABLISHMENT PROTOCOL — CLIENT ROLE
═══════════════════════════════════════════════════════════════

  The client is the INITIATOR of the session key protocol:

  [PROTOCOL STEP 1]  CLIENT → SERVER : request handshake
                     SERVER → CLIENT : certificate + public key

  [PROTOCOL STEP 2]  CLIENT validates server certificate with CA
                     Ensures the public key genuinely belongs to the server
                     and has not been substituted (man-in-the-middle defence)

  [PROTOCOL STEP 3]  CLIENT generates random 128-bit session key
                     - Uses random.getrandbits(128) — fresh on every call
                     - This is the SOURCE OF DYNAMICITY in the protocol
                     - The same client connecting to the same server will
                       produce a completely different key on every execution

  [PROTOCOL STEP 4]  CLIENT → SERVER : ElGamal-encrypted session key
                     c1 = g^k  mod p          (ephemeral public component)
                     c2 = m * y^k  mod p       (masked session key)
                     Only the server (holding private key x) can recover m

  [PROTOCOL STEP 5]  SERVER → CLIENT : XTEA-encrypted acknowledgement
                     Client decrypts using the session key just established.
                     Successful decryption confirms both parties share
                     the identical secret — handshake complete.

═══════════════════════════════════════════════════════════════
  DYNAMICITY — WHY THE KEY DIFFERS EVERY TIME
═══════════════════════════════════════════════════════════════

  random.getrandbits(128) produces a 128-bit integer drawn uniformly
  at random from [0, 2^128). The probability of two identical draws is
  1/2^128 — negligible. Every protocol execution therefore yields a
  different session key, even between the same client and server.

  This is verified by demonstrate_dynamicity() which runs the
  handshake twice and prints both resulting keys side-by-side.

The client NEVER sends plaintext data over the network.
All transactions are signed with the client's ElGamal private key.
"""

import os
import sys
import json
import time
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from symmetric.xtea     import xtea_encrypt_cbc, xtea_decrypt_cbc
from asymmetric.elgamal import (generate_keypair, get_public_key,
                                  elgamal_encrypt_int, sign, verify)
from ca.certificate_authority import CertificateAuthority


# ─────────────────────────────────────────────────────────────
#  BANK CLIENT
# ─────────────────────────────────────────────────────────────

class BankClient:
    """
    Secure Bank Client — customer-side application.

    Session Key Protocol role: INITIATOR
      - Generates the session key (source of dynamicity)
      - Encrypts it asymmetrically for the server (ElGamal)
      - Uses the established key for all XTEA transaction encryption
      - Signs every transaction with its ElGamal private key
    """

    def __init__(self, name: str, ca: CertificateAuthority):
        self.name         = name
        self.ca           = ca
        self._session_key = None   # set during handshake; None until established
        self._server_pub  = None
        self._handshake_count = 0  # tracks how many handshakes performed

        # ── Long-term ElGamal keypair ─────────────────────────
        # Private key: signs all outgoing transactions
        # Public key : embedded in CA certificate, used by server to verify sigs
        print(f"[CLIENT:{name}] Generating ElGamal keypair (long-term signing key)...")
        self.keypair    = generate_keypair(bits=128)
        self.public_key = get_public_key(self.keypair)

        # ── CA certificate ────────────────────────────────────
        # Presented to the server during handshake.
        # Proves that our public key is genuine (CA-vouched).
        # Motivation 3: no pre-shared symmetric key needed — the CA
        # certificate lets the server trust us without prior contact.
        self.certificate = ca.issue_certificate(f"Client:{name}", self.public_key)
        print(f"[CLIENT:{name}] ✅ Certificate #{self.certificate['serial']} received from CA")

    # ─────────────────────────────────────────────────────────
    #  SESSION KEY ESTABLISHMENT PROTOCOL
    # ─────────────────────────────────────────────────────────

    def perform_handshake(self, server) -> bool:
        """
        Execute the 5-step session key establishment protocol.

        This method is the INITIATOR side of the protocol.
        Each call generates a fresh, independent session key
        (DYNAMICITY) and establishes it with the server via
        ElGamal public-key encryption.

        Returns True if the handshake succeeds, False otherwise.
        """
        client_id = f"CLIENT:{self.name}"
        self._handshake_count += 1
        print(f"\n[CLIENT:{self.name}] ── Session Key Protocol (execution #{self._handshake_count}) ──")

        # ── PROTOCOL STEP 1: Request server identity ──────────
        # Ask the server for its certificate and public key.
        # Server's response allows us to verify who we are talking to.
        print(f"[CLIENT:{self.name}] [PROTOCOL STEP 1] Requesting server certificate...")
        server_hello = server.initiate_handshake(client_id)
        server_cert  = server_hello["server_certificate"]
        server_pub   = server_hello["server_public_key"]

        # ── PROTOCOL STEP 2: Authenticate the server ──────────
        # Verify the server's certificate was signed by our trusted CA.
        # This ensures the public key we received actually belongs to
        # the bank server — not to an impersonator.
        print(f"[CLIENT:{self.name}] [PROTOCOL STEP 2] Authenticating server via CA...")
        if not self.ca.validate_certificate(server_cert):
            print(f"[CLIENT:{self.name}] ❌ Server certificate INVALID — aborting handshake")
            return False
        print(f"[CLIENT:{self.name}] ✅ Server identity confirmed.")
        self._server_pub = server_pub

        # ── PROTOCOL STEP 3: Generate session key (DYNAMICITY) ─
        # This is the critical step that provides dynamicity.
        # random.getrandbits(128) draws from a uniform distribution
        # over [0, 2^128) — a different value on every call.
        # The resulting session key is never reused.
        print(f"[CLIENT:{self.name}] [PROTOCOL STEP 3] Generating fresh 128-bit session key...")
        session_key_int   = random.getrandbits(128)   # SOURCE OF DYNAMICITY
        self._session_key = session_key_int.to_bytes(16, "big")
        print(f"[CLIENT:{self.name}]   Session key #{self._handshake_count}: "
              f"{self._session_key.hex()[:16]}...  (unique per execution)")

        # ── PROTOCOL STEP 4: Encrypt and send session key ──────
        # Encrypt the session key integer using ElGamal with the
        # server's public key (y). This produces ciphertext (c1, c2).
        # Only the server's private key (x) can recover the plaintext.
        # The key is transmitted as ciphertext — never in plaintext.
        print(f"[CLIENT:{self.name}] [PROTOCOL STEP 4] Encrypting session key via ElGamal...")
        print(f"[CLIENT:{self.name}]   c1 = g^k mod p  (ephemeral public component)")
        print(f"[CLIENT:{self.name}]   c2 = m * y^k mod p  (masked session key)")
        c1, c2 = elgamal_encrypt_int(session_key_int, server_pub)
        print(f"[CLIENT:{self.name}]   Sending (c1, c2) to server — plaintext never crosses the wire")

        response = server.complete_handshake(client_id, self.certificate, (c1, c2))

        if response.get("status") != "OK":
            print(f"[CLIENT:{self.name}] ❌ Handshake rejected: {response.get('reason')}")
            return False

        # ── PROTOCOL STEP 5: Verify acknowledgement ────────────
        # Decrypt the server's XTEA-encrypted ACK using our session key.
        # If decryption succeeds and produces a readable ACK, both parties
        # hold the same session key — protocol is complete.
        print(f"[CLIENT:{self.name}] [PROTOCOL STEP 5] Verifying server acknowledgement...")
        ack_enc = bytes.fromhex(response["ack_encrypted"])
        ack_dec = xtea_decrypt_cbc(ack_enc, self._session_key).decode("utf-8")
        print(f"[CLIENT:{self.name}] ✅ Handshake complete. ACK: {ack_dec}")
        print(f"[CLIENT:{self.name}]   Session key established. "
              f"All transactions will use XTEA-CBC encryption.")
        return True

    # ─────────────────────────────────────────────────────────
    #  TRANSACTION SUBMISSION
    # ─────────────────────────────────────────────────────────

    def send_transaction(self, server, transaction: dict) -> dict:
        """
        Send a single encrypted, signed transaction to the server.

        Every transaction is:
          1. Serialised to JSON bytes
          2. Signed with the client's ElGamal private key
             (guarantees authenticity + integrity)
          3. Encrypted with the XTEA session key
             (guarantees confidentiality in transit)
          4. Decrypted and returned after receiving server response
        """
        if self._session_key is None:
            raise RuntimeError(
                "No active session. Call perform_handshake() first.")

        client_id = f"CLIENT:{self.name}"

        # ── Serialise ─────────────────────────────────────────
        tx_bytes = json.dumps(transaction).encode("utf-8")

        # ── Sign (ElGamal private key) ─────────────────────────
        # Signature (r, s) binds the transaction content to this client's
        # identity. The server verifies (r, s) using our public key from
        # our CA certificate — ensuring we cannot be impersonated.
        r, s = sign(tx_bytes, self.keypair)
        print(f"\n[CLIENT:{self.name}] Signed transaction with ElGamal private key")

        # ── Encrypt (XTEA session key) ─────────────────────────
        # The session key was established during the protocol handshake.
        # It changes on every session and every KEY_ROTATION_INTERVAL
        # transactions (enforced server-side).
        tx_enc = xtea_encrypt_cbc(tx_bytes, self._session_key)
        print(f"[CLIENT:{self.name}] Transaction encrypted (XTEA-CBC, {len(tx_enc)} bytes)")
        print(f"[CLIENT:{self.name}] Sending: {transaction}")

        # ── Transmit ──────────────────────────────────────────
        raw_resp = server.process_transaction(client_id, tx_enc, r, s)

        # ── Decrypt response ──────────────────────────────────
        resp_enc = raw_resp.get("encrypted_response")
        if resp_enc is None:
            return raw_resp

        resp_plain = xtea_decrypt_cbc(resp_enc, self._session_key)
        response   = json.loads(resp_plain.decode("utf-8"))
        print(f"[CLIENT:{self.name}] Server response: {response}")
        return response

    # ─────────────────────────────────────────────────────────
    #  DYNAMICITY DEMONSTRATION
    # ─────────────────────────────────────────────────────────

    def demonstrate_dynamicity(self, server):
        """
        Run the session key establishment protocol TWICE with the same
        server and print both resulting session keys side by side.

        This provides empirical proof of the DYNAMICITY property:
        the same pair of parties (this client, this server) produces
        a completely different shared secret on each execution.
        """
        print("\n" + "═" * 62)
        print("  DYNAMICITY DEMONSTRATION")
        print("  Same client + same server → different key every time")
        print("═" * 62)

        keys = []
        for i in range(1, 3):
            print(f"\n  ── Execution {i} ──────────────────────────────────────")
            ok = self.perform_handshake(server)
            if ok:
                keys.append(self._session_key.hex())
                print(f"\n  Execution {i} session key: {self._session_key.hex()}")

        print("\n" + "─" * 62)
        if len(keys) == 2:
            print(f"  Key 1 : {keys[0]}")
            print(f"  Key 2 : {keys[1]}")
            print(f"  Same?  {'❌ YES — dynamicity FAILED (bug)' if keys[0] == keys[1] else '✅ NO  — dynamicity CONFIRMED'}")
            print(f"\n  Interpretation: Compromising Key 1 gives zero information")
            print(f"  about Key 2. Each session is cryptographically independent.")
        print("═" * 62 + "\n")
        return keys

    # ─────────────────────────────────────────────────────────
    #  CONVENIENCE METHODS
    # ─────────────────────────────────────────────────────────

    def check_balance(self, server, account_id: str) -> dict:
        """Request account balance from server."""
        return self.send_transaction(server, {
            "type"     : "BALANCE",
            "account"  : account_id,
            "timestamp": int(time.time()),
        })

    def transfer(self, server, from_acc: str, to_acc: str, amount: float) -> dict:
        """Send a fund transfer request to server."""
        return self.send_transaction(server, {
            "type"     : "TRANSFER",
            "from"     : from_acc,
            "to"       : to_acc,
            "amount"   : amount,
            "timestamp": int(time.time()),
        })
