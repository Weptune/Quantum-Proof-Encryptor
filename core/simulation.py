# core/simulation.py
import numpy as np
import math

# ---------------------------
# Attack cost models & utils
# ---------------------------

def attack_difficulty(scheme, param, idn_params=None):
    """
    Return (classical_cost, quantum_cost) baseline numbers.
    param: security parameter (bits or lattice dimension)
    idn_params: dict with keys 'robustness_factor' and 'noise_strength' (optional)
    """
    # base classical/quantum scaling exponents (heuristic models)
    if scheme == "RSA":
        Cc = param ** 3.0
        Cq = (param ** 2.0) * np.log2(param)
    elif scheme == "ECC":
        Cc = param ** 2.5
        Cq = param ** 1.3 * param  # slightly larger multiplier
    elif scheme == "LWE":
        Cc = param ** 2.8
        Cq = param ** 2.4
    elif scheme == "IDN-LWE":
        # Base IDN-LWE baseline is slightly higher than plain LWE;
        # we allow idn_params to further increase difficulty.
        base_exp = 2.7
        Cc = param ** (base_exp + 0.2)
        Cq = param ** (base_exp)
    else:
        Cc = param ** 2.5
        Cq = param ** 2.0

    # Apply IDN-specific multipliers when provided (only affects IDN-LWE)
    if scheme == "IDN-LWE" and idn_params is not None:
        robustness = float(idn_params.get("robustness_factor", 0.0))
        noise = float(idn_params.get("noise_strength", 0.0))

        # Increase the *effective exponent* for quantum cost slightly per robustness unit.
        # This models algorithmic changes that increase asymptotic hardness.
        exponent_boost = 0.04 * robustness   # each robustness unit adds 0.04 to exponent
        Cq = param ** (base_exp + exponent_boost)

        # Increase multiplicative constant depending on noise
        # noise_strength of 0..2 multiplies quantum cost by 1..(1+noise*1.5) roughly
        noise_mult = 1.0 + (noise * 1.5)
        Cq = Cq * noise_mult

        # Also slightly inflate classical cost for fairness (optional)
        Cc = Cc * (1.0 + 0.25 * robustness)

    return float(Cc), float(Cq)


def attack_success(time_array, complexity):
    """
    Generic success probability (classical or quantum) w.r.t time and complexity.
    time_array: numpy array of times (positive)
    complexity: scalar representative cost (higher => slower success)
    returns: probability array 0..1
    """
    # Use a smooth sigmoid whose slope depends on complexity:
    # when complexity large, growth is slower.
    time_array = np.array(time_array, dtype=float)
    # scale factor: larger complexity -> smaller k (slower)
    k = 5.0 / (complexity ** 0.35 + 1e-12)
    center = complexity ** 0.5
    return 1.0 / (1.0 + np.exp(-k * (time_array - center)))


def quantum_attack_success(time_array, classical_cost, quantum_cost, advantage_factor=1.0):
    """
    Specialized quantum success model.
    advantage_factor > 1 means quantum attacker has extra advantage (e.g., more qubits / improved algorithm).
    We reduce effective quantum_cost by advantage_factor (i.e. speedup).
    """
    adjusted_cost = float(quantum_cost) / max(1.0, float(advantage_factor))
    return attack_success(time_array, adjusted_cost)


# ---------------------------
# Helper for plotting comparative gap
# ---------------------------

def cost_ratio_log10(classical_cost, quantum_cost):
    """Return log10 ratio quantum/classical (useful to visualize gap)."""
    if classical_cost <= 0 or quantum_cost <= 0:
        return 0.0
    return math.log10(quantum_cost / classical_cost)
