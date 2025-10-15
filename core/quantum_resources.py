# core/quantum_resources.py
"""
Heuristic quantum resource estimator for attacking cryptosystems.

Provides simple, transparent models to estimate:
 - logical qubit counts
 - T-gate counts (or approximate expensive gate counts)
 - wall-clock time given gate time and parallelism assumptions
 - physical qubits given error-correction overhead

Models implemented (heuristic):
 - RSA (Shor-like period-finding)
 - ECC (ECDLP via Shor)
 - Symmetric brute-force (Grover)
 - LWE / IDN-LWE (very rough lattice-quantum cost model)

All numbers are *estimates*. Parameters are exposed to allow tuning.
"""

import math

# -------------------------
# Utilities
# -------------------------

def to_human(n):
    """Human-friendly string for large integers."""
    if n >= 1e12:
        return f"{n/1e12:.2f}T"
    if n >= 1e9:
        return f"{n/1e9:.2f}B"
    if n >= 1e6:
        return f"{n/1e6:.2f}M"
    if n >= 1e3:
        return f"{n/1e3:.2f}k"
    return str(n)

# -------------------------
# RSA / ECC resource heuristics
# -------------------------

def estimate_shor_rsa(rsa_bits, gate_time_ns=10.0, physical_error_rate=1e-3,
                      logical_error_target=1e-12, t_depth_scaling=1.0):
    """
    Heuristic estimate for resources to factor an RSA modulus of rsa_bits using Shor-like circuit.

    Returns dict with logical_qubits, t_count, depth_estimate, wall_time_seconds, physical_qubits_est.
    - gate_time_ns: assumed logical gate time in nanoseconds
    - physical_error_rate: physical gate error rate (used to estimate overhead)
    - logical_error_target: desired overall logical failure prob
    - t_depth_scaling: tunable constant to scale T-depth (tradeoff parameter)
    """
    n = rsa_bits

    # Heuristics (transparent constants):
    # Logical qubits: proportional to rsa_bits (registers, control, ancilla)
    logical_qubits = max(8, int(2.5 * n))  # ~2.5 * n
    # T-count: assume ~ c * n^3 scaling for arithmetic (schoolbook modular exponentiation)
    # Use c ~ 0.5 as baseline (tunable)
    c = 0.5 * t_depth_scaling
    t_count = int(c * (n ** 3))
    # depth (sequential layers of expensive gates)
    t_depth = int(0.25 * (n ** 2) * t_depth_scaling)  # heuristic

    # wall-clock: assume T-gates dominate; if fully sequential:
    gate_time_s = gate_time_ns * 1e-9
    wall_time_seconds = t_depth * gate_time_s

    # Error-correction overhead -> physical qubits per logical qubit:
    # crude estimate: physical_per_logical ~ 1000 * (physical_error_rate / 1e-3)^-0.5
    # Lower physical_error_rate reduces overhead.
    phys_mult = max(50, int(1000 * (1e-3 / max(physical_error_rate, 1e-12))**0.5))
    physical_qubits_est = logical_qubits * phys_mult

    return {
        "scheme": "RSA (Shor)",
        "rsa_bits": rsa_bits,
        "logical_qubits": logical_qubits,
        "t_count": t_count,
        "t_depth": t_depth,
        "wall_time_s": wall_time_seconds,
        "physical_qubits_est": physical_qubits_est,
        "notes": {
            "model": "heuristic: logical_qubits ~ 2.5*n; t_count ~ c*n^3",
            "c": c,
            "phys_mult": phys_mult
        }
    }

def estimate_shor_ecc(curve_bits, gate_time_ns=10.0, physical_error_rate=1e-3):
    """
    Heuristic estimate for breaking ECC (ECDLP) using Shor.
    curve_bits: bit-size of the curve order (e.g., 256)
    """
    n = curve_bits
    # ECC tends to require fewer qubits than RSA of same bit-length.
    logical_qubits = max(8, int(4.0 * n))  # heuristic
    # T-count: use ~ c * n^2.5
    c = 1.0
    t_count = int(c * (n ** 2.5))
    t_depth = int(0.2 * (n ** 1.8))

    gate_time_s = gate_time_ns * 1e-9
    wall_time_seconds = t_depth * gate_time_s

    phys_mult = max(50, int(1000 * (1e-3 / max(physical_error_rate, 1e-12))**0.5))
    physical_qubits_est = logical_qubits * phys_mult

    return {
        "scheme": "ECC (Shor)",
        "curve_bits": curve_bits,
        "logical_qubits": logical_qubits,
        "t_count": t_count,
        "t_depth": t_depth,
        "wall_time_s": wall_time_seconds,
        "physical_qubits_est": physical_qubits_est,
        "notes": {
            "model": "heuristic: logical_qubits ~ 4*n; t_count ~ n^2.5"
        }
    }

# -------------------------
# Grover (Symmetric) heuristic
# -------------------------

def estimate_grover_symmetric(key_bits, parallelism=1, gate_time_ns=10.0,
                              oracle_cost_multiplier=1.0):
    """
    Estimate resources for Grover search to recover an AES-like key of key_bits.
    - parallelism: number of parallel quantum machines working in parallel (reduces time)
    - oracle_cost_multiplier: scales the cost of one oracle evaluation in T-depth
    """
    k = key_bits
    # Number of oracle calls (sequential Grover iterations) ~ pi/4 * 2^(k/2)
    iterations = max(1, int((math.pi / 4.0) * (2 ** (k / 2.0))))
    # Each iteration requires several quantum gates; assume per-iteration T-depth ~ d_oracle
    base_oracle_depth = max(10, int(20 * (k / 128)))  # heuristic: small for small keys
    t_depth_total = int(iterations * base_oracle_depth * oracle_cost_multiplier)
    # logical qubits: need k qubits for key register + ancilla ~ k + 100
    logical_qubits = int(k + 200)
    # wall time assuming perfectly sequential Grover on single machine:
    gate_time_s = gate_time_ns * 1e-9
    wall_time_s = t_depth_total * gate_time_s / max(1, parallelism)

    # physical overhead
    phys_mult = 1000  # default
    physical_qubits_est = logical_qubits * phys_mult

    return {
        "scheme": "Grover (symm)",
        "key_bits": key_bits,
        "iterations": iterations,
        "logical_qubits": logical_qubits,
        "t_depth_total": t_depth_total,
        "wall_time_s": wall_time_s,
        "physical_qubits_est": physical_qubits_est,
        "notes": {
            "model": "iterations ~ pi/4 * 2^(k/2); per-iteration depth heuristic"
        }
    }

# -------------------------
# LWE / IDN-LWE heuristic (very rough)
# -------------------------

def estimate_lattice_attack(n_param, q_modulus=None, idn_params=None,
                            gate_time_ns=10.0, physical_error_rate=1e-3):
    """
    Very rough estimate for quantum resources to attack LWE-style schemes.
    - n_param: lattice dimension / security parameter
    - idn_params: dict containing 'robustness_factor' and 'noise_strength' as used earlier
    Model: we convert the 'quantum cost' exponent from simulation.attack_difficulty into a T-count
    and assume logical qubits proportional to n_param * log(n_param).
    """
    base_exp = 2.7
    robustness = 0.0
    noise = 0.0
    if idn_params:
        robustness = float(idn_params.get("robustness_factor", 0.0))
        noise = float(idn_params.get("noise_strength", 0.0))

    # effective exponent used earlier: base_exp + 0.04*robustness
    eff_exp = base_exp + 0.04 * robustness
    # approximate quantum T-count ~ k * n_param^eff_exp where k scales with noise
    kfactor = 1.0 + (noise * 1.5)
    t_count = int(kfactor * (n_param ** eff_exp))

    # logical qubits: scale ~ n * log n
    logical_qubits = int(max(16, n_param * max(4, int(math.log2(max(2, n_param))))))

    # estimate T-depth as t_count / parallelism_factor (assume some parallelism)
    t_depth = int(t_count ** 0.9)  # heuristic: depth grows sublinearly in count
    gate_time_s = gate_time_ns * 1e-9
    wall_time_s = t_depth * gate_time_s

    phys_mult = max(50, int(1000 * (1e-3 / max(physical_error_rate, 1e-12))**0.5))
    physical_qubits_est = logical_qubits * phys_mult

    return {
        "scheme": "LWE/IDN-LWE (heuristic)",
        "n_param": n_param,
        "logical_qubits": logical_qubits,
        "t_count": t_count,
        "t_depth": t_depth,
        "wall_time_s": wall_time_s,
        "physical_qubits_est": physical_qubits_est,
        "notes": {
            "effective_exponent": eff_exp,
            "kfactor_noise": kfactor
        }
    }


# -------------------------
# Top-level estimator
# -------------------------

def estimate_resources(kind, param, **kwargs):
    """
    Unified interface.
    kind: 'rsa', 'ecc', 'grover', 'lwe'
    param: rsa_bits (int) for rsa, curve_bits for ecc, key_bits for grover, n_param for lwe.
    kwargs pass to specific models.
    """
    kind = kind.lower()

    if kind == "rsa":
        return estimate_shor_rsa(param, **kwargs)
    elif kind == "ecc":
        return estimate_shor_ecc(param, **kwargs)
    elif kind == "grover":
        return estimate_grover_symmetric(param, **kwargs)
    elif kind in ("lwe", "idn-lwe"):
        # extract idn_params separately so it isn’t passed twice
        idn_params = kwargs.pop("idn_params", None)
        return estimate_lattice_attack(param, idn_params=idn_params, **kwargs)
    else:
        raise ValueError("Unknown kind")

