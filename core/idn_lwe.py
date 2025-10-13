# core/idn_lwe.py
# Lightweight IDN-LWE prototype for demo (educational only)

import hashlib, random, base64, secrets

def keygen(q=4093, n=8, m=16, t_base=3):
    """Generate a toy IDN-LWE keypair"""
    s = [random.randrange(q) for _ in range(n)]
    pub = []
    for i in range(m):
        a = [random.randrange(q) for _ in range(n)]
        e = random.randint(-t_base, t_base)
        b = (sum(ai*si for ai,si in zip(a, s)) + e) % q
        pub.append((a, b))
    pk_id = hashlib.sha256(str(pub[:4]).encode()).digest()
    return (pub, pk_id), s

def encrypt_bit(pk_tuple, bit, q=4093, t_base=3, MAX_T_OFFSET=4):
    """Encrypt a single bit (demo only)."""
    pub, pk_id = pk_tuple
    r = secrets.token_bytes(8)
    h = hashlib.sha256(pk_id + r + bytes([bit])).digest()
    offset = int.from_bytes(h, 'big') % MAX_T_OFFSET
    t_prime = t_base + offset
    n = len(pub[0][0])
    S = random.sample(range(len(pub)), max(1, len(pub)//4))
    A = [0]*n; B = 0
    for i in S:
        a_i, b_i = pub[i]
        A = [(Ai+ai) % q for Ai, ai in zip(A, a_i)]
        B = (B + b_i) % q
    seed = hashlib.sha256(pk_id + r + bytes([bit])).digest()
    rnd = int.from_bytes(seed, 'big')
    E = sum(((rnd := (rnd*1103515245+12345)&0xFFFFFFFFFFFF) % (2*t_prime+1)) - t_prime for _ in S)
    C = (B + E + (q//2 if bit else 0)) % q
    return r, A, C

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
