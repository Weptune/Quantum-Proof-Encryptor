import os, base64, json, hashlib, hmac, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from core import idn_lwe  # for shared perf_log

# -----------------------------------
# AES (GCM) - Hybrid Symmetric Crypto
# -----------------------------------

def aes_encrypt(data: bytes):
    """Encrypt short plaintext using AES-GCM."""
    t0 = time.time()
    key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    duration_ms = (time.time() - t0) * 1000
    idn_lwe.log_perf("encrypt", "AES-GCM", duration_ms)
    return key, nonce, ct


def aes_decrypt(key: bytes, nonce: bytes, ct: bytes):
    t0 = time.time()
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, None)
    duration_ms = (time.time() - t0) * 1000
    idn_lwe.log_perf("decrypt", "AES-GCM", duration_ms)
    return pt


# -----------------------------------
# AES Stream Encryption (chunked)
# -----------------------------------

def aes_encrypt_stream(f):
    """Encrypts file-like object stream in chunks."""
    t0 = time.time()
    key = AESGCM.generate_key(bit_length=128)
    base_nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    chunks_b64 = []
    chunk_size = 1024 * 32
    i = 0
    while True:
        chunk = f.read(chunk_size)
        if not chunk:
            break
        nonce = (int.from_bytes(base_nonce, "big") + i).to_bytes(12, "big")
        ct = aesgcm.encrypt(nonce, chunk, None)
        chunks_b64.append(base64.b64encode(ct).decode())
        i += 1
    duration_ms = (time.time() - t0) * 1000
    idn_lwe.log_perf("encrypt", "AES-stream", duration_ms)
    return key, base_nonce, chunks_b64


def aes_decrypt_stream(key: bytes, base_nonce: bytes, chunks_b64):
    t0 = time.time()
    aesgcm = AESGCM(key)
    output = b""
    for i, chunk64 in enumerate(chunks_b64):
        nonce = (int.from_bytes(base_nonce, "big") + i).to_bytes(12, "big")
        ct = base64.b64decode(chunk64)
        output += aesgcm.decrypt(nonce, ct, None)
    duration_ms = (time.time() - t0) * 1000
    idn_lwe.log_perf("decrypt", "AES-stream", duration_ms)
    return output


# -----------------------------------
# Hybrid Payload Builders
# -----------------------------------

def build_payload(metadata, wrapdict, nonce, aes_ct):
    return {
        "metadata": metadata,
        "wrap": wrapdict,
        "aes": {
            "nonce": base64.b64encode(nonce).decode(),
            "ct": base64.b64encode(aes_ct).decode()
        }
    }


def build_payload_stream(metadata, wrapdict, base_nonce, chunks_b64):
    return {
        "metadata": metadata,
        "wrap": wrapdict,
        "aes_stream": {
            "base_nonce": base64.b64encode(base_nonce).decode(),
            "chunks": chunks_b64
        }
    }


# -----------------------------------
# Integrity Tag (HMAC) for demo audit
# -----------------------------------

def sign_payload_hmac(key, payload_bytes: bytes):
    return hmac.new(key, payload_bytes, hashlib.sha256).digest()


def verify_payload_hmac(key, payload_bytes: bytes, tag: bytes):
    calc = hmac.new(key, payload_bytes, hashlib.sha256).digest()
    return hmac.compare_digest(calc, tag)
