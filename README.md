# 🏦 Secure Banking System — Cryptography Coursework

A fully integrated, end-to-end encrypted banking application implementing custom
cryptographic algorithms **from scratch** — no encryption libraries used.

---

## 📦 Project Structure

```
secure_banking_system/
├── symmetric/
│   ├── xtea.py              # XTEA block cipher (from scratch)
│   ├── twofish.py           # Twofish block cipher (from scratch)
│   └── file_encryptor.py    # File encryption CLI (uses XTEA or Twofish)
├── asymmetric/
│   └── elgamal.py           # ElGamal encryption + digital signatures (from scratch)
├── ca/
│   └── certificate_authority.py   # CA: issues & validates certificates
├── network/
│   ├── bank_server.py       # Bank server (Twofish at-rest + XTEA in-transit)
│   └── bank_client.py       # Bank client (ElGamal key exchange + XTEA session)
├── performance/
│   └── benchmarks.py        # Runtime, memory, and ciphertext ratio analysis
├── data/                    # Encrypted account storage (auto-generated)
├── main.py                  # Full end-to-end demo
└── README.md
```

---

## 🔧 Requirements

- Python **3.10+** (uses `list[int]` type hints)
- **No external libraries required** — only Python standard library
- Standard library modules used: `struct`, `os`, `hashlib`, `random`, `json`, `time`, `math`

---

## 🚀 Quick Start

### 1. Clone / Download the project

```bash
cd secure_banking_system
```

### 2. Run the full end-to-end demo

```bash
python main.py
```

This runs all 7 phases:
- CA setup and certificate issuance
- Server initialisation with Twofish at-rest encryption
- Client registration
- TLS-style handshake with ElGamal key exchange
- Encrypted + signed transactions (balance check, transfer, overdraft rejection)
- Session key rotation
- Handwritten verification traces (XTEA + ElGamal)
- Audit log

### 3. Run with performance benchmarks

```bash
python main.py --benchmark
```
### 3. Run with GUI

```bash
python gui.py
```

---

## 🔐 Algorithm-Specific Tests

### XTEA Cipher (symmetric)
```bash
python symmetric/xtea.py
```
Outputs:
- 2-round hand-verification trace (small values)
- Full 64-round CBC self-test

### Twofish Cipher (symmetric)
```bash
python symmetric/twofish.py
```
Outputs:
- Full 16-round CBC self-test

### ElGamal (asymmetric)
```bash
python asymmetric/elgamal.py
```
Outputs:
- Small-prime hand-verification trace
- 128-bit key exchange demo
- Digital signature test + tamper detection

### Certificate Authority
```bash
python ca/certificate_authority.py
```
Outputs:
- CA key generation
- Certificate issuance for server and client
- Revocation test
- Tamper detection test

---

## 📁 File Encryption CLI

Encrypt a file using Twofish (default) or XTEA:

```bash
# Encrypt with Twofish (at-rest, banking-grade)
python symmetric/file_encryptor.py encrypt data/report.txt data/report.enc --algo twofish

# Encrypt with XTEA (session tokens, lightweight)
python symmetric/file_encryptor.py encrypt data/session.txt data/session.enc --algo xtea

# Decrypt
python symmetric/file_encryptor.py decrypt data/report.enc data/report_dec.txt --algo twofish

# Custom password
python symmetric/file_encryptor.py encrypt input.txt output.enc --password MyBankPass!
```

---

## 🧮 Cryptographic Design

### Symmetric Algorithms

| Feature | XTEA-CBC | Twofish-CBC |
|---|---|---|
| Block size | 64-bit | 128-bit |
| Key size | 128-bit | 128-bit |
| Rounds | 64 | 16 |
| Structure | Feistel | Feistel + MDS + PHT |
| Math used | XOR, +, shifts | XOR, GF(2^8) mult, S-boxes |
| Banking use | Session tokens (transit) | Account records (at rest) |
| Speed (1KB) | ~4.5 ms | ~42 ms |

### Asymmetric Algorithm

| Feature | ElGamal |
|---|---|
| Security basis | Discrete Logarithm Problem |
| Key size | 128-bit (demo), scalable |
| Math used | `pow(base, exp, mod)` only |
| Operations | Encryption, decryption, signing, verification |
| Banking use | Key exchange + transaction signatures |

### Key Management Flow

```
1. CA generates ElGamal root keypair
2. Server requests certificate → CA signs + issues
3. Client requests certificate → CA signs + issues
4. Handshake: client validates server cert with CA
5. Client generates random 128-bit session key
6. Client encrypts session key with server's ElGamal public key
7. Server decrypts session key with its private key
8. All transactions encrypted with XTEA using session key
9. All transactions signed with client's ElGamal private key
10. Account data encrypted at rest with Twofish
11. Session keys rotated periodically by server
```

---

## 📊 Performance Summary

| Algorithm | 1KB Encrypt | 10KB Encrypt | CT Ratio |
|---|---|---|---|
| XTEA-CBC | ~4.5 ms | ~46 ms | 1.016 |
| Twofish-CBC | ~42 ms | ~382 ms | 1.003 |
| ElGamal-128 | 0.15 ms | N/A (key exchange only) | 3.8x |

---

## ⚠️ Academic Notice

This software is implemented for educational purposes. All algorithms are
hand-coded from mathematical specifications to satisfy course requirements.
Do **not** use this in production systems — use audited libraries such as
OpenSSL or libsodium for real-world applications.

---

## 👥 Team Contributions

| Member | Responsibility |
|---|---|
| Member 1 | XTEA implementation, file encryptor, handwritten XTEA verification |
| Member 2 | Twofish implementation, CA simulation, server module |
| Member 3 | ElGamal implementation, client module, benchmarks, report |

---

## 📚 References

See full report for 10+ academic citations (Schneier et al., ElGamal 1985,
Needham & Wheeler 1997, NIST FIPS standards, etc.)
