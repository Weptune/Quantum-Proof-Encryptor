# core/hybrid_crypto.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def aes_encrypt(plaintext: bytes, aad=b"demo"):
    """Encrypt plaintext using AES-GCM, returning (key, nonce, ciphertext)."""
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, aad)
    return key, nonce, ct

def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad=b"demo"):
    """Decrypt ciphertext using AES-GCM."""
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
