import numpy as np

def map_costs(scheme, param):
    if scheme in ("RSA", "ECC"):
        classical = 10**(0.0025 * param)
        quantum = 0.0001 * param**3
    else:
        classical = 10**(0.01 * param)
        quantum = 10**(0.009 * param)
    return classical, quantum

def attack_success(times, cost):
    """Model success probability over time."""
    return 1 - np.exp(-np.array(times) / float(cost))

def time_to_reach_probability(times, curve, target=0.9):
    idx = np.argmax(curve >= target)
    if curve[idx] < target:
        return None
    return times[idx]
