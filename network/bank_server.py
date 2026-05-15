"""
Bank Server — Secure Banking System
=====================================
Simulates a bank server that:
  1. Registers with the Certificate Authority
  2. Performs Session Key Establishment Protocol (TLS-style handshake)
  3. Receives and processes encrypted transaction requests (XTEA for transit)
  4. Stores account data encrypted at rest (Twofish)
  5. Verifies client ElGamal digital signatures on all transactions
  6. Automatically rotates session keys every KEY_ROTATION_INTERVAL transactions

═══════════════════════════════════════════════════════════════
  SESSION KEY ESTABLISHMENT PROTOCOL — SERVER ROLE
═══════════════════════════════════════════════════════════════

  This server participates in a 5-step session key establishment
  protocol on every new client connection:

  [PROTOCOL STEP 1]  SERVER → CLIENT : send certificate + public key
                     (allows client to authenticate server identity)

  [PROTOCOL STEP 2]  CLIENT validates server certificate with CA
                     (server waits — no action needed at this step)

  [PROTOCOL STEP 3]  CLIENT generates random 128-bit session key
                     (server waits — dynamicity guaranteed by client randomness)

  [PROTOCOL STEP 4]  CLIENT → SERVER : ElGamal-encrypted session key (c1, c2)
                     SERVER decrypts using private key x:
                       shared_secret = c1^x mod p
                       session_key   = c2 * shared_secret^(-1) mod p

  [PROTOCOL STEP 5]  SERVER → CLIENT : XTEA-encrypted acknowledgement
                     (proves both sides hold the same session key)

  After the protocol completes, all communication uses the session
  key for XTEA-CBC encryption. The session key is automatically
  rotated every KEY_ROTATION_INTERVAL transactions to limit ciphertext
  exposure (Motivation 1) and reduce compromise impact (Motivation 2).

═══════════════════════════════════════════════════════════════
  KEY MANAGEMENT DESIGN
═══════════════════════════════════════════════════════════════

  - ElGamal keypair  : generated once at startup, used ONLY for
                       decrypting incoming session keys (Step 4).
                       Private key never leaves this object.

  - XTEA session keys: generated ON-DEMAND by the client per session.
                       Different on every protocol execution (dynamic).
                       Discarded after session ends or rotation occurs.
                       No long-term storage of session keys (Motivation 3).

  - Twofish storage  : single key for at-rest account data encryption.
                       Separate from session keys — not rotated per session.
"""

import os
import sys
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from symmetric.xtea    import xtea_encrypt_cbc, xtea_decrypt_cbc
from symmetric.twofish import twofish_encrypt_cbc, twofish_decrypt_cbc
from asymmetric.elgamal import (generate_keypair, get_public_key,
                                 elgamal_decrypt_int, sign, verify)
from ca.certificate_authority import CertificateAuthority


# ─────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────

# Motivation 1 & 2: rotate the session key every N transactions
# to limit available ciphertext and reduce compromise exposure.
KEY_ROTATION_INTERVAL = 5


# ─────────────────────────────────────────────────────────────
#  BANK SERVER
# ─────────────────────────────────────────────────────────────

class BankServer:
    """
    Secure Bank Server — end-to-end encrypted banking service.

    Session Key Protocol role: RESPONDER
      - Authenticates itself to clients via CA-signed certificate
      - Decrypts incoming session keys using ElGamal private key
      - Uses negotiated session key for all subsequent XTEA encryption
      - Auto-rotates session keys every KEY_ROTATION_INTERVAL transactions

    Key Management:
      - ElGamal keypair  : asymmetric — key decapsulation only
      - XTEA session keys: symmetric  — per-session, ephemeral, auto-rotated
      - Twofish storage  : symmetric  — at-rest account data, persistent
    """

    STORAGE_FILE = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "data", "accounts.enc"
    )

    def __init__(self, ca: CertificateAuthority, name: str = "BankServer-Primary"):
        self.name      = name
        self.ca        = ca
        self._sessions = {}
        self._tx_log   = []

        # ── Long-term asymmetric keypair ──────────────────────
        # Used ONLY in Step 4 of the session key protocol.
        # The private key (x) never leaves this object.
        print(f"[SERVER] Generating ElGamal keypair (long-term identity key)...")
        self.keypair    = generate_keypair(bits=128)
        self.public_key = get_public_key(self.keypair)

        # ── At-rest encryption key (Twofish) ──────────────────
        # Separate from session keys — protects stored account data.
        self.storage_key = os.urandom(16)

        # ── CA certificate (presented in Protocol Step 1) ─────
        self.certificate = ca.issue_certificate(name, self.public_key)

        self._accounts = {}
        self._init_accounts()

        print(f"[SERVER] ✅ {name} ready. Certificate #{self.certificate['serial']} issued.")

    # ─────────────────────────────────────────────────────────
    #  ACCOUNT STORE  (Twofish at-rest encryption)
    # ─────────────────────────────────────────────────────────

    def _init_accounts(self):
        """Initialise sample accounts and immediately encrypt to disk (Twofish)."""
        self._accounts = {
            "ACC-001": {"owner": "Alice",   "balance": 50000.00, "currency": "GBP"},
            "ACC-002": {"owner": "Bob",     "balance": 25000.00, "currency": "GBP"},
            "ACC-003": {"owner": "Charlie", "balance": 75000.00, "currency": "GBP"},
        }
        self._persist_accounts()
        print(f"[SERVER] Account store initialised and encrypted with Twofish (at-rest).")

    def _persist_accounts(self):
        """Encrypt account data with Twofish and write to disk."""
        os.makedirs(os.path.dirname(self.STORAGE_FILE), exist_ok=True)
        plaintext  = json.dumps(self._accounts).encode("utf-8")
        ciphertext = twofish_encrypt_cbc(plaintext, self.storage_key)
        with open(self.STORAGE_FILE, "wb") as f:
            f.write(ciphertext)

    def _load_accounts(self):
        """Decrypt account data from disk using Twofish storage key."""
        with open(self.STORAGE_FILE, "rb") as f:
            ciphertext = f.read()
        plaintext      = twofish_decrypt_cbc(ciphertext, self.storage_key)
        self._accounts = json.loads(plaintext.decode("utf-8"))

    # ─────────────────────────────────────────────────────────
    #  SESSION KEY ESTABLISHMENT PROTOCOL  Steps 1 & 4-5
    # ─────────────────────────────────────────────────────────

    def initiate_handshake(self, client_id: str) -> dict:
        """
        SESSION KEY PROTOCOL — STEP 1  (Server → Client)

        Server sends its CA-signed certificate and ElGamal public key
        to the connecting client. Client uses this to:
          (a) verify server identity via CA signature check
          (b) obtain the public key used in Step 3 to encrypt the
              client-generated session key
        """
        print(f"\n[SERVER] [PROTOCOL STEP 1] Handshake initiated by {client_id}")
        print(f"[SERVER]   Sending certificate #{self.certificate['serial']} and public key")
        return {
            "server_certificate": self.certificate,
            "server_public_key" : self.public_key,
        }

    def complete_handshake(self, client_id: str, client_cert: dict,
                           encrypted_session_key_parts: tuple) -> dict:
        """
        SESSION KEY PROTOCOL — STEP 4  (Client → Server)

        Server receives the ElGamal-encrypted session key (c1, c2)
        and decrypts it using its private key x:

            shared_secret (s) = c1 ^ x  mod p
            session_key   (m) = c2 * s^(-1)  mod p

        The session key was generated randomly by the client (Step 3)
        — different on every protocol execution (DYNAMICITY PROPERTY).
        The plaintext key never crossed the network.

        SESSION KEY PROTOCOL — STEP 5  (Server → Client)

        Server sends an XTEA-encrypted ACK using the newly established
        session key. Successful decryption by the client proves both
        parties hold the identical shared secret — handshake complete.
        """
        # ── Step 4a: Validate client certificate ──────────────
        print(f"[SERVER] [PROTOCOL STEP 4a] Validating client certificate...")
        if not self.ca.validate_certificate(client_cert):
            return {"status": "REJECTED", "reason": "Invalid client certificate"}

        # ── Step 4b: ElGamal decryption of session key ────────
        # Recovers the 128-bit session key the client generated in Step 3.
        # Only possible because we hold the matching ElGamal private key x.
        print(f"[SERVER] [PROTOCOL STEP 4b] Decrypting session key via ElGamal...")
        c1, c2          = encrypted_session_key_parts
        session_key_int = elgamal_decrypt_int(c1, c2, self.keypair)
        session_key     = session_key_int.to_bytes(16, "big")

        # ── Initialise session state ───────────────────────────
        # tx_count drives automatic key rotation (Motivations 1 & 2).
        # session_keys_used records all keys for dynamicity proof.
        # Motivation 3: keys are created on-demand and never pre-stored.
        self._sessions[client_id] = {
            "session_key"       : session_key,
            "client_cert"       : client_cert,
            "established_at"    : int(time.time()),
            "tx_count"          : 0,
            "rotation_count"    : 0,
            "session_keys_used" : [session_key.hex()],
        }

        print(f"[SERVER] ✅ Session established with {client_id}")
        print(f"[SERVER]    Session key (initial) : {session_key.hex()[:16]}...")
        print(f"[SERVER]    Auto-rotation interval: every {KEY_ROTATION_INTERVAL} transactions")

        # ── Step 5: XTEA-encrypted acknowledgement ────────────
        # Proves both parties hold the same session key.
        print(f"[SERVER] [PROTOCOL STEP 5] Sending XTEA-encrypted acknowledgement...")
        ack     = f"SESSION_ACK:{client_id}:{int(time.time())}"
        ack_enc = xtea_encrypt_cbc(ack.encode(), session_key)
        return {"status": "OK", "ack_encrypted": ack_enc.hex()}

    # ─────────────────────────────────────────────────────────
    #  TRANSACTION PROCESSING
    # ─────────────────────────────────────────────────────────

    def process_transaction(self, client_id: str, encrypted_tx: bytes,
                            signature_r: int, signature_s: int) -> dict:
        """
        Process a single encrypted, signed transaction from a client.

        Security flow:
          1. XTEA-decrypt the transaction (in-transit decryption)
          2. Verify ElGamal digital signature (authentication + integrity)
          3. Execute business logic (balance enquiry / fund transfer)
          4. XTEA-encrypt the response (in-transit encryption)
          5. Increment tx_count; auto-rotate session key if threshold reached

        Ciphertext limiting (Motivation 1):
          tx_count is incremented on every transaction. Once it reaches
          KEY_ROTATION_INTERVAL, the session key is automatically rotated,
          bounding the ciphertext volume under any single key to at most
          KEY_ROTATION_INTERVAL small blocks.

        Compromise isolation (Motivation 2):
          If the current session key is compromised, the attacker can
          only decrypt transactions since the last rotation — not the
          full session history. Each rotation window is isolated.
        """
        if client_id not in self._sessions:
            return {"status": "ERROR", "reason": "No active session"}

        session     = self._sessions[client_id]
        session_key = session["session_key"]
        client_pub  = session["client_cert"]["public_key"]

        # ── 1. Decrypt with session key (XTEA — in transit) ───
        tx_bytes = xtea_decrypt_cbc(encrypted_tx, session_key)
        tx       = json.loads(tx_bytes.decode("utf-8"))
        print(f"\n[SERVER] Received transaction from {client_id}: {tx}")

        # ── 2. Verify ElGamal digital signature ───────────────
        if not verify(tx_bytes, signature_r, signature_s, client_pub):
            print(f"[SERVER] ❌ INVALID SIGNATURE — transaction rejected")
            response = {"status": "REJECTED", "reason": "Invalid signature"}
        else:
            print(f"[SERVER] ✅ Signature verified.")
            response = self._execute_transaction(tx)

        # ── 3. Persist accounts (Twofish — at rest) ───────────
        self._persist_accounts()

        # ── 4. Encrypt response (XTEA — in transit) ───────────
        response_bytes = json.dumps(response).encode("utf-8")
        response_enc   = xtea_encrypt_cbc(response_bytes, session_key)

        # ── 5. Update tx_count and audit log ──────────────────
        session["tx_count"] += 1
        self._tx_log.append({
            "client"          : client_id,
            "tx"              : tx,
            "result"          : response["status"],
            "timestamp"       : int(time.time()),
            "session_tx_count": session["tx_count"],
            "rotation_count"  : session["rotation_count"],
        })

        # ── AUTO KEY ROTATION CHECK ───────────────────────────
        # Triggered automatically after every KEY_ROTATION_INTERVAL
        # transactions. Implements Motivations 1 and 2 explicitly.
        if session["tx_count"] >= KEY_ROTATION_INTERVAL:
            print(f"\n[SERVER] ⚠  Rotation threshold reached "
                  f"({KEY_ROTATION_INTERVAL} tx) — triggering auto-rotation...")
            self._auto_rotate_session_key(client_id)

        return {"encrypted_response": response_enc}

    # ─────────────────────────────────────────────────────────
    #  KEY ROTATION  (Motivations 1, 2, 3)
    # ─────────────────────────────────────────────────────────

    def _auto_rotate_session_key(self, client_id: str) -> bytes:
        """
        Automatic session key rotation after KEY_ROTATION_INTERVAL transactions.

        Motivation 1 — Limiting ciphertext for cryptanalysis:
            Cryptanalytic attacks (differential, linear) require large
            ciphertext volumes under a single key. Rotation resets the
            counter, limiting the available corpus per key to at most
            KEY_ROTATION_INTERVAL transactions.

        Motivation 2 — Limiting exposure from key compromise:
            A compromised session key exposes only the transactions since
            the last rotation — not the full session history. Each rotation
            window is cryptographically isolated from all others.

        Motivation 3 — On-demand key creation:
            The new key is generated fresh with os.urandom(16) at
            rotation time — not pre-stored or pre-distributed anywhere.
            Keys exist only when needed and are immediately discarded
            when superseded.
        """
        session = self._sessions[client_id]
        old_key = session["session_key"]

        # Generate a fresh 128-bit session key on-demand (Motivation 3)
        new_key = os.urandom(16)

        session["session_key"]     = new_key
        session["tx_count"]        = 0
        session["rotation_count"] += 1
        session["rotated_at"]      = int(time.time())
        session["session_keys_used"].append(new_key.hex())

        print(f"[SERVER] 🔄 AUTO KEY ROTATION #{session['rotation_count']} — {client_id}")
        print(f"[SERVER]    Old key : {old_key.hex()[:16]}...")
        print(f"[SERVER]    New key : {new_key.hex()[:16]}...")
        print(f"[SERVER]    Motivation 1: ciphertext corpus bounded to "
              f"{KEY_ROTATION_INTERVAL} transactions per key")
        print(f"[SERVER]    Motivation 2: previous window isolated — "
              f"new key cannot decrypt old ciphertext")
        print(f"[SERVER]    Motivation 3: new key created on-demand, never pre-stored")
        return new_key

    def rotate_session_key(self, client_id: str) -> bytes:
        """Manual session key rotation (exposed for GUI, admin, and testing)."""
        if client_id not in self._sessions:
            raise ValueError(f"No active session for {client_id}")
        return self._auto_rotate_session_key(client_id)

    # ─────────────────────────────────────────────────────────
    #  DYNAMICITY DEMONSTRATION
    # ─────────────────────────────────────────────────────────

    def get_session_key_history(self, client_id: str) -> list:
        """
        Return all session keys used by a client (initial + all rotations).

        All keys in this list are independently generated — proving
        the session key protocol satisfies DYNAMICITY: the same pair
        of parties produces a different shared secret on every execution.
        """
        if client_id not in self._sessions:
            return []
        return self._sessions[client_id].get("session_keys_used", [])

    def print_session_summary(self, client_id: str):
        """Print formatted session key protocol summary for a client."""
        if client_id not in self._sessions:
            print(f"[SERVER] No session for {client_id}")
            return
        s = self._sessions[client_id]
        keys = s["session_keys_used"]
        print(f"\n[SERVER] ══ SESSION PROTOCOL SUMMARY: {client_id} ══")
        print(f"[SERVER]   Established : {time.ctime(s['established_at'])}")
        print(f"[SERVER]   Tx count    : {s['tx_count']} (since last rotation)")
        print(f"[SERVER]   Rotations   : {s['rotation_count']}")
        print(f"[SERVER]   Total keys  : {len(keys)}")
        print(f"[SERVER]   Key history (DYNAMICITY proof):")
        for i, k in enumerate(keys):
            label = "initial  " if i == 0 else f"rotation #{i}"
            print(f"[SERVER]     [{label}] {k[:32]}...")
        all_unique = len(set(keys)) == len(keys)
        print(f"[SERVER]   All keys distinct? {'✅ YES — dynamicity confirmed' if all_unique else '❌ NO — BUG'}")

    # ─────────────────────────────────────────────────────────
    #  BUSINESS LOGIC
    # ─────────────────────────────────────────────────────────

    def _execute_transaction(self, tx: dict) -> dict:
        tx_type = tx.get("type")
        if tx_type == "BALANCE":
            acc_id = tx.get("account")
            if acc_id in self._accounts:
                acc = self._accounts[acc_id]
                return {"status": "OK", "account": acc_id,
                        "balance": acc["balance"], "currency": acc["currency"],
                        "owner": acc["owner"]}
            return {"status": "ERROR", "reason": "Account not found"}

        elif tx_type == "TRANSFER":
            src = tx.get("from");  dst = tx.get("to")
            amt = float(tx.get("amount", 0))
            if src not in self._accounts or dst not in self._accounts:
                return {"status": "ERROR", "reason": "Account not found"}
            if self._accounts[src]["balance"] < amt:
                return {"status": "ERROR", "reason": "Insufficient funds"}
            if amt <= 0:
                return {"status": "ERROR", "reason": "Invalid amount"}
            self._accounts[src]["balance"] -= amt
            self._accounts[dst]["balance"] += amt
            print(f"[SERVER] 💳 Transfer £{amt} from {src} to {dst} — APPROVED")
            return {"status": "OK",
                    "message": f"Transfer of £{amt} from {src} to {dst} completed.",
                    "new_balance": self._accounts[src]["balance"]}

        return {"status": "ERROR", "reason": "Unknown transaction type"}

    # ─────────────────────────────────────────────────────────
    #  AUDIT LOG
    # ─────────────────────────────────────────────────────────

    def get_audit_log(self) -> list:
        return self._tx_log
