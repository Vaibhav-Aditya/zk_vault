"""
Symmetric encryption helpers (AES-256-GCM) for vault file storage.
The server stores files encrypted with a key derived from the user's
public key — so even the server cannot decrypt them without the client.
"""

import hashlib
import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_file_key(public_key: int, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the user's Schnorr public key + salt."""
    key_material = public_key.to_bytes((public_key.bit_length() + 7) // 8, "big")
    return hashlib.scrypt(key_material, salt=salt, n=2**14, r=8, p=1, dklen=32)


def encrypt_file(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt data with AES-256-GCM.
    Returns (nonce, ciphertext_with_tag).
    """
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce, ciphertext


def decrypt_file(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext. Raises on auth failure."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)