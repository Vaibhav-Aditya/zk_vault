import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# returns a key for the encryption
def derive_file_key(private_key: int, salt: bytes) -> bytes:
    key_material = private_key.to_bytes((private_key.bit_length() + 7) // 8, "big")
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

# derive a key to encrypt the 'encryption key'
def derive_envelope_key(shared_secret: int) -> bytes:
    secret_bytes = shared_secret.to_bytes(
        (shared_secret.bit_length() + 7) // 8, "big"
    )
    return hashlib.sha256(secret_bytes).digest()

# encrypt 'encryption key' using the key
def wrap_key(file_key: bytes, envelope_key: bytes) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(envelope_key)
    wrapped = aesgcm.encrypt(nonce, file_key, None)
    return nonce, wrapped

# retrieve the 'encryption key'
def unwrap_key(nonce: bytes, wrapped: bytes, envelope_key: bytes) -> bytes:
    aesgcm = AESGCM(envelope_key)
    return aesgcm.decrypt(nonce, wrapped, None)