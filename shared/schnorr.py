"""
Schnorr Identification Protocol - Zero Knowledge Proof Primitives
=================================================================
Uses a safe prime group for the discrete logarithm problem.

Protocol:
  1. Registration: Client computes public key Y = g^x mod p (x is secret)
  2. Prover (Client) picks random r, sends commitment T = g^r mod p
  3. Verifier (Server) sends challenge c (random integer)
  4. Prover responds with s = (r - c*x) mod q
  5. Verifier checks g^s * Y^c mod p == T
"""

import hashlib
import os
import secrets

# ── Safe 2048-bit prime group (RFC 3526, Group 14) ──────────────────────────
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2          # generator
Q = (P - 1) // 2  # sub-group order (safe prime: P = 2Q + 1)


def generate_keypair() -> tuple[int, int]:
    """Generate a Schnorr keypair.
    Returns (private_key x, public_key Y) where Y = g^x mod p.
    x must be in [1, Q-1].
    """
    x = secrets.randbelow(Q - 1) + 1
    Y = pow(G, x, P)
    return x, Y


def generate_commitment() -> tuple[int, int]:
    """Prover step 1: pick random r, return (r, T=g^r mod p)."""
    r = secrets.randbelow(Q - 1) + 1
    T = pow(G, r, P)
    return r, T


def generate_challenge() -> int:
    """Verifier step: generate a random challenge c."""
    return secrets.randbelow(Q - 1) + 1


def generate_response(r: int, c: int, x: int) -> int:
    """Prover step 2: compute response s = (r - c*x) mod Q."""
    return (r - c * x) % Q


def verify(Y: int, T: int, c: int, s: int) -> bool:
    """Verifier step: check g^s * Y^c ≡ T (mod P)."""
    lhs = (pow(G, s, P) * pow(Y, c, P)) % P
    return lhs == T


def hash_challenge(T: int, username: str, nonce: bytes) -> int:
    """Fiat-Shamir heuristic: derive c deterministically (optional helper)."""
    h = hashlib.sha256()
    h.update(T.to_bytes((T.bit_length() + 7) // 8, "big"))
    h.update(username.encode())
    h.update(nonce)
    return int.from_bytes(h.digest(), "big") % Q