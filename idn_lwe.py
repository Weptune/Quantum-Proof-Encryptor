# core/idn_lwe.py
import hashlib, random, base64, secrets, json, time

# Defaults tuned for demo speed
DEFAULT_PARAMS = {"q": 4093, "n": 8, "m": 16, "t_base": 3}

def keygen(q=4093, n=8, m=16, t_base=3):
    s = [random.randrange(q) for _ in range(n)]
    pub = []
    for i in range(m):
        a = [random.randrange(q) for _ in range(n)]
        e = random.randint(-t_base, t_base)
        b = (sum(ai*si for ai,si in zip(a, s)) + e) % q
        pub.append((a, b))
    pk_id = hashlib.sha256(str(pub[:4]).encode()).digest()
    pk = {"pub": pub, "pk_id": base64.b64encode(pk_id).decode(), "params": {"q": q, "n": n, "m": m, "t_base": t_base}}
    return pk, s

def export_public_key(pk):
    # pk is dict: make a JSON-safe compact export (pub elements large; do simple serialization)
    return json.dumps(pk)

def import_public_key(pk_json):
    return json.loads(pk_json)

# Simple deterministic single-bit encrypt (same as earlier but adapted to pk dict)
def encrypt_bit(pk_dict, bit, MAX_T_OFFSET=4):
    pub = pk_dict["pub"]
    pk_id = base64.b64decode(pk_dict["pk_id"])
    q = pk_dict["params"]["q"]
    r = secrets.token_bytes(8)
    h = hashlib.sha256(pk_id + r + bytes([bit])).digest()
    offset = int.from_bytes(h, 'big') % MAX_T_OFFSET
    t_prime = pk_dict["params"]["t_base"] + offset
    S = random.sample(range(len(pub)), max(1, len(pub)//4))
    n = pk_dict["params"]["n"]
    A = [0]*n; B=0
    for i in S:
        a_i, b_i = pub[i]
        A = [(Ai+ai) % q for Ai, ai in zip(A, a_i)]
        B = (B + b_i) % q
    seed = hashlib.sha256(pk_id + r + bytes([bit])).digest()
    rnd = int.from_bytes(seed, 'big')
    E = sum(((rnd := (rnd*1103515245+12345)&0xFFFFFFFFFFFF) % (2*t_prime+1)) - t_prime for _ in S)
    C = (B + E + (q//2 if bit else 0)) % q
    return {"r": base64.b64encode(r).decode(), "A": A, "C": C}

def decrypt_bit(sk, ct, q=4093):
    r = base64.b64decode(ct["r"])
    A = ct["A"]; C = ct["C"]
    inner = sum(ai*si for ai,si in zip(A, sk)) % q
    val = (C - inner) % q
    val = val - q if val > q//2 else val
    return 1 if abs(val) > q//4 else 0

# Fast mock-wrapping: instead of bit-by-bit, produce a compact wrapped object (HMAC-like)
# This is useful to demo real-world UX without heavy CPU.

import base64, os

def fast_wrap_key(pk, key: bytes):
    """
    Mock-fast wrap function (for demo).
    Simulates fast lattice-based key encapsulation but does NOT use real PQ crypto.
    """
    wrapped = base64.b64encode(key[::-1]).decode()  # reversible mock
    return {
        "method": "idn-fast",
        "wrapped_key": wrapped,
        "note": "mock fast wrap; not real PQ security"
    }


def wrap_key(pk, key: bytes):
    """
    Bitwise educational wrap: slower, more explicit but still demo-only.
    """
    bits = [b for b in key]
    noisy = [(x ^ (pk[i % len(pk)] & 0xFF)) for i, x in enumerate(bits)]
    return noisy


def unwrap_key(sk, wrapdata):
    """
    Reverse of wrap_key() for demo. Works only with 'bitwise' wrap.
    """
    if isinstance(wrapdata, list):
        bits = [(x ^ (sk[i % len(sk)] & 0xFF)) for i, x in enumerate(wrapdata)]
        return bytes(bits)
    raise ValueError("Cannot unwrap mock-fast mode key")
