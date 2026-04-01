import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# returns a key for the encryption
def derive_file_key(public_key: int, salt: bytes) -> bytes:
    key_material = public_key.to_bytes((public_key.bit_length() + 7) // 8, "big")
    return hashlib.scrypt(key_material, salt=salt, n=2**14, r=8, p=1, dklen=32)

# encrypts the file and return tuple of (nonce, ciphertext)
def encrypt_file(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce, ciphertext

# decrypts the file using the key
def decrypt_file(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)