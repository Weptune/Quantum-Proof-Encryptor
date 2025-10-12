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

def decrypt_bit(sk, ct, q=4093):
    """Decrypt a single bit (demo only)."""
    r, A, C = ct
    inner = sum(ai*si for ai,si in zip(A, sk)) % q
    val = (C - inner) % q
    val = val - q if val > q//2 else val
    return 1 if abs(val) > q//4 else 0

def wrap_key(pk_tuple, key_bytes, q=4093):
    """Wrap a short AES key bitwise (demo; slow)."""
    bits = []
    for byte in key_bytes:
        for i in range(8):
            bit = (byte >> i) & 1
            r, A, C = encrypt_bit(pk_tuple, bit, q=q)
            bits.append({'r': base64.b64encode(r).decode(), 'A': A, 'C': C})
    return bits

def unwrap_key(sk, wrapped_bits, q=4093):
    """Recover AES key from wrapped bits (demo)."""
    out = []
    for i in range(0, len(wrapped_bits), 8):
        byte = 0
        for j in range(8):
            entry = wrapped_bits[i+j]
            r = base64.b64decode(entry['r'])
            A = entry['A']; C = entry['C']
            bit = decrypt_bit(sk, (r, A, C), q=q)
            byte |= (bit << j)
        out.append(byte)
    return bytes(out)
