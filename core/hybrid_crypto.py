# core/hybrid_crypto.py
import os, json, base64, time, hmac, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- AES-GCM helpers (non-streaming for small payloads) ---
def aes_encrypt(plaintext: bytes, aad: bytes = b"pq-demo"):
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, aad)
    return key, nonce, ct

def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"pq-demo"):
    return AESGCM(key).decrypt(nonce, ciphertext, aad)

# --- Streaming / chunked AE (encrypt large files in chunks) ---
# We'll implement a simple chunking scheme:
# - Generate AES key and nonce
# - Encrypt in chunks with AESGCM by incrementing a 96-bit nonce counter
# WARNING: This is a demo streaming approach. For production, use an authenticated streaming AEAPI.
def _inc_nonce(nonce: bytes, counter: int):
    # nonce is 12 bytes; treat last 4 bytes as counter
    prefix = nonce[:8]
    ctr = int.from_bytes(nonce[8:], 'big') + counter
    return prefix + (ctr % (1 << 32)).to_bytes(4, 'big')

def aes_encrypt_stream(fileobj, chunk_size=64*1024, aad=b"pq-demo"):
    """
    fileobj: binary file-like (readable)
    returns: (key, base_nonce, list_of_chunks_base64)
    Each chunk is AESGCM.encrypt(nonce_i, chunk, aad=b'...').
    """
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    base_nonce = os.urandom(12)
    chunks_b64 = []
    counter = 0
    while True:
        chunk = fileobj.read(chunk_size)
        if not chunk:
            break
        nonce_i = _inc_nonce(base_nonce, counter)
        ct = aes.encrypt(nonce_i, chunk, aad)
        chunks_b64.append(base64.b64encode(ct).decode())
        counter += 1
    return key, base_nonce, chunks_b64

def aes_decrypt_stream(key, base_nonce, chunks_b64, chunk_size=64*1024, aad=b"pq-demo"):
    aes = AESGCM(key)
    out = bytearray()
    for i, ctb64 in enumerate(chunks_b64):
        nonce_i = _inc_nonce(base_nonce, i)
        ct = base64.b64decode(ctb64)
        chunk = aes.decrypt(nonce_i, ct, aad)
        out.extend(chunk)
    return bytes(out)

# --- packaging helpers (produce a single JSON payload) ---
def build_payload(metadata: dict, wrapdict: dict, aes_nonce: bytes, aes_ct: bytes):
    """
    metadata: dict of metadata
    wrapdict: dict describing wrapped key (KEM ciphertext or IDN-LWE wrapped bits)
    aes_nonce: bytes
    aes_ct: bytes
    returns JSON-serializable dict
    """
    payload = {
        "metadata": metadata,
        "wrap": wrapdict,
        "aes": {
            "nonce": base64.b64encode(aes_nonce).decode(),
            "ct": base64.b64encode(aes_ct).decode()
        }
    }
    return payload

def build_payload_stream(metadata: dict, wrapdict: dict, base_nonce: bytes, chunks_b64: list):
    payload = {
        "metadata": metadata,
        "wrap": wrapdict,
        "aes_stream": {
            "base_nonce": base64.b64encode(base_nonce).decode(),
            "chunks": chunks_b64
        }
    }
    return payload

# --- simple HMAC audit tag (demo only) ---
def sign_payload_hmac(key: bytes, payload_bytes: bytes):
    # key: symmetric key used only for HMAC; in real systems use a dedicated signer
    tag = hmac.new(key, payload_bytes, hashlib.sha256).digest()
    return tag

def verify_payload_hmac(key: bytes, payload_bytes: bytes, tag: bytes):
    expected = hmac.new(key, payload_bytes, hashlib.sha256).digest()
    return hmac.compare_digest(expected, tag)
