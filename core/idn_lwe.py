import os, base64, hashlib, json, time

# -----------------------------
#   IDN-LWE Educational Model
# -----------------------------

def keygen(n=256):
    """Generate a simple educational LWE-style keypair (mock).
       Now stores the same random seed in both pk and sk so wrap/unwrap are consistent.
    """
    seed_bytes = os.urandom(16)
    seed_b64 = base64.b64encode(seed_bytes).decode()

    pk = {
        "a": [os.urandom(1)[0] for _ in range(n)],
        "b": [os.urandom(1)[0] for _ in range(n)],
        "params": {"n": n, "seed": seed_b64}
    }
    sk = {
        "s": [os.urandom(1)[0] for _ in range(n)],
        "params": {"n": n, "seed": seed_b64}
    }
    return pk, sk


# --------------------------------------------------------
# Global performance log helper
# --------------------------------------------------------
perf_log = []

def log_perf(action, scheme, duration_ms):
    perf_log.append({
        "action": action,
        "scheme": scheme,
        "time_ms": duration_ms,
        "timestamp": time.time()
    })


# --------------------------------------------------------
# Key Wrapping — Educational (Mock + Bitwise)
# --------------------------------------------------------

def fast_wrap_key(pk, key: bytes):
    """Fast but mock key wrapping (noisy hash-based mask)."""
    t0 = time.time()
    pk_bytes = json.dumps(pk).encode()
    mask = hashlib.sha256(pk_bytes).digest()
    wrapped = base64.b64encode(bytes([(k ^ mask[i % len(mask)]) for i, k in enumerate(key)])).decode()
    duration_ms = (time.time() - t0) * 1000
    log_perf("wrap", "idn-fast", duration_ms)
    return {"method": "idn-fast", "data": wrapped, "time_ms": duration_ms}


def wrap_key(pk, key: bytes):
    """
    Bitwise educational wrap using a deterministic seed stored in pk['params']['seed'].
    Returns a list of masked byte integers (reversible by unwrap_key).
    """
    pk_seed_b64 = pk.get("params", {}).get("seed")
    if not pk_seed_b64:
        # fallback: hash pk if no seed present (but we prefer explicit seed)
        seed_bytes = hashlib.sha256(str(pk).encode()).digest()
    else:
        seed_bytes = base64.b64decode(pk_seed_b64)

    bits = [b for b in key]
    noisy = [(x ^ seed_bytes[i % len(seed_bytes)]) for i, x in enumerate(bits)]
    return noisy


def unwrap_key(sk, wrapdata):
    """
    Reverse of wrap_key(): uses seed in sk['params']['seed'] to unmask.
    Returns bytes (the AES key).
    """
    sk_seed_b64 = sk.get("params", {}).get("seed")
    if not sk_seed_b64:
        seed_bytes = hashlib.sha256(str(sk).encode()).digest()
    else:
        seed_bytes = base64.b64decode(sk_seed_b64)

    if isinstance(wrapdata, list):
        bits = [(x ^ seed_bytes[i % len(seed_bytes)]) for i, x in enumerate(wrapdata)]
        return bytes(bits)
    raise ValueError("unwrap_key: expected bitwise list wrapdata")


# --------------------------------------------------------
# Key import/export utilities
# --------------------------------------------------------

def export_public_key(pk):
    return json.dumps(pk, indent=2)

def import_public_key(pk_json: str):
    return json.loads(pk_json)
