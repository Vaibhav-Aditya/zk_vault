<div align="center">

# ZK Authentication Vault

### Zero-Knowledge Proof File Storage using the Schnorr Identification Protocol
---
</div>

## How It Works

### The Core Idea

Traditional authentication sends a password (or its hash) to the server. If the server is breached, those stored values can be attacked. This project takes a different approach: the client **proves it knows a secret** without ever revealing the secret.

This is a **Zero-Knowledge Proof** — specifically the **Schnorr Identification Protocol**.

### Schnorr ZKP — Authentication Flow

```
        CLIENT                                    SERVER
   ─────────────────────────────────────────────────────────────

   REGISTER
   ─────────
   Generate secret x  ─── { username, Y = g^x mod p } ───────►  store(username, Y)
   Save x locally

   LOGIN  (3 messages, private key never leaves client)
   ──────
   Pick random r
   T = g^r mod p       ─── { username, T } ──────────────────►  store T in session

                       ◄── { session_id, c } ─────────────────  random challenge c

   s = (r - c*x) mod q ─── { session_id, s } ────────────────►  verify: g^s * Y^c = T (mod p)?
                                                                  OK  -> issue JWT (1 hour)
                                                                  FAIL -> reject
```

**Why this is secure:**
- `x` (your private key) **never crosses the network**, not even once
- The server stores only `Y = g^x mod p` — recovering `x` requires solving the 2048-bit Discrete Logarithm Problem, estimated at more than 2^112 operations
- A captured transcript `(T, c, s)` is **computationally useless** — the protocol is honest-verifier zero-knowledge

### File Encryption — End-to-End

Every file is encrypted on your machine before upload using **AES-256-GCM**:

```
salt    = random 32 bytes
key     = scrypt(public_key_bytes, salt)     <- memory-hard KDF
nonce   = random 12 bytes
bundle  = salt | nonce | AES-GCM(key, plaintext)
                               ^
                               uploaded to server (server cannot decrypt)
```

### File Sharing — Diffie-Hellman Envelope Encryption

Sharing a file does not require re-encrypting it. Instead, a small cryptographic "envelope" is created:

```
ALICE shares with BOB
──────────────────────────────────────────────────────────────
Generate ephemeral keypair:  r,  R = g^r mod p
Fetch Bob's public key:      Y_bob
Compute shared secret:       shared = Y_bob ^ r mod p
Wrap Alice's file key:       k_env = SHA-256(shared)
                             wrapped_k = AES-GCM(k_env, file_key)
Discard r (forward secrecy)  Send (R, wrapped_k) to server

BOB downloads
──────────────────────────────────────────────────────────────
Fetch envelope from server:  (R, wrapped_k)
Recover shared secret:       shared = R ^ x_bob mod p  <- same value
Unwrap file key:             k_env = SHA-256(shared)
                             file_key = AES-GCM-Dec(k_env, wrapped_k)
Decrypt file normally
```

The server never sees `file_key`. Breaking the envelope requires solving the Computational Diffie-Hellman problem.

---

## 🚀 Quick Start

The method to run client is described here as server is already deployed on render and available at https://zk-auth-vault.onrender.com
### Prerequisites

- Python 3.12+
- pip

### 1. Clone and Install

```bash
git clone https://github.com/Vaibhav-Aditya/zk_vault.git
cd zk-auth-vault

# Client
pip install -r client/requirements.txt
```

### 2. Start the Client

```bash
python client/client.py --server https://zk-auth-vault.onrender.com
```

---

## 💻 Commands

### All Available Commands

| Command | Description |
|---------|-------------|
| `register` | Generate a Schnorr keypair and register with the server |
| `login` | Authenticate via ZKP handshake, receive JWT |
| `upload` | Encrypt a local file and upload to your vault |
| `list` | List all files in your vault |
| `download` | Download and decrypt a vault file |
| `delete` | Permanently delete a vault file |
| `share` | Share a file with another registered user |
| `shared` | List files shared with you; optionally download |
| `revoke` | Revoke a previously created share |
| `logout` | Clear the local session token |
| `exit` | Quit the client |

## 📁 Project Structure

```
zk-auth-vault/
|
+-- shared/
|   +-- schnorr.py
|   +-- crypto_utils.py
|
+-- server/
|   +-- main.py
|   +-- requirements.txt
|
+-- client/
|   +-- client.py
|   +-- requirements.txt
|
+-- render.yaml
+-- README.md
```

---

## 📡 API Reference

### Authentication

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/auth/register` | — | Register (username + public key Y) |
| `POST` | `/auth/challenge` | — | Submit commitment T, receive challenge c |
| `POST` | `/auth/verify` | — | Submit response s, receive JWT |

### Vault

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/vault/upload` | JWT | Upload encrypted file bundle |
| `GET` | `/vault/list` | JWT | List your vault files |
| `GET` | `/vault/download/{id}` | JWT | Download encrypted bundle |
| `DELETE` | `/vault/delete/{id}` | JWT | Delete a file |

### Sharing

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/users/{username}/pubkey` | JWT | Fetch any user's public key |
| `POST` | `/vault/share` | JWT | Create a DH share envelope |
| `GET` | `/vault/shared-with-me` | JWT | List files shared with you |
| `GET` | `/vault/my-shares` | JWT | List shares you have created |
| `DELETE` | `/vault/share/{share_id}` | JWT | Revoke a share |

### Utility

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Server health check |
| `GET` | `/docs` | Swagger UI — interactive API explorer |
| `GET` | `/redoc` | ReDoc documentation |

---

## 🛡️ Security

### What the Server Stores (and What It Reveals)

| Stored Value | Can Server Decrypt/Reverse It? | Reason |
|---|---|---|
| Public key `Y = g^x mod p` | No | 2048-bit DLP — no polynomial-time algorithm |
| Encrypted file bundles | No | AES-256-GCM key is never stored |
| File metadata (name, size) | Yes (metadata only) | No file contents |
| Share envelope `(R, wrapped_k)` | No | CDH — needs recipient's private key |

### Security Properties

| Property | Status | How |
|---|---|---|
| Private key never transmitted | ✅ | Schnorr ZKP |
| Server breach does not expose credentials | ✅ | DLP hardness |
| Server breach does not expose files | ✅ | AES-256-GCM + client-side keys |
| Replay attack resistance | ✅ | Single-use sessions, 120s TTL |
| MITM resistance | ✅ | TLS on Render |
| Sharing without exposing file key | ✅ | CDH assumption |
| Forward secrecy on shares | ✅ | Ephemeral r discarded after use |
| Share revocation | ✅ | Envelope deletion |

### Known Limitations

| Limitation | Mitigation |
|---|---|
| JWT is a Bearer token — stolen token = impersonation | Shorten expiry, add revocation list, use DPoP (RFC 9449) |
| TinyDB has no concurrent write protection | Migrate to PostgreSQL for production |
| Private key stored in plaintext on disk | Add Argon2id passphrase wrapping |
| No rate limiting on auth endpoints | Add `slowapi` (5 req/min) |
| Vulnerable to Shor's algorithm (quantum) | Migrate to ML-KEM + ML-DSA (NIST FIPS 203/204) |
| Filenames stored in plaintext | Encrypt filenames client-side before upload |
---