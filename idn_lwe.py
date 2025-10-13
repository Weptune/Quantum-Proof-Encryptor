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

def fast_wrap_key(pk_dict, key_bytes):
    # produce a "wrapped token" which is H = SHA256(pk_id || key)
    pk_id = base64.b64decode(pk_dict["pk_id"])
    h = hashlib.sha256(pk_id + key_bytes).digest()
    return {"method": "idn-fast-wrap", "h": base64.b64encode(h).decode()}
def wrap_key(pk_dict, key_bytes):
    """
    Real (bitwise) IDN-LWE wrapping of an AES key.
    Slow but fully reversible — educational mode.
    """
    q = pk_dict["params"]["q"]
    bits = []
    for byte in key_bytes:
        for i in range(8):
            bit = (byte >> i) & 1
            ct = encrypt_bit(pk_dict, bit)
            bits.append(ct)
    return bits


def unwrap_key(sk, wrapped_bits):
    """
    Recover AES key from wrapped bits.
    """
    # For decryption, we need the same q used in keygen
    q = 4093
    out = []
    for i in range(0, len(wrapped_bits), 8):
        byte = 0
        for j in range(8):
            ct = wrapped_bits[i + j]
            bit = decrypt_bit(sk, ct, q=q)
            byte |= (bit << j)
        out.append(byte)
    return bytes(out)

# Unwrap is impossible for fast mock (this is for demo: real unwrap requires secret)
# Provide a note in UI when using fast_wrap.
