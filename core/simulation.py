import numpy as np
from core import idn_lwe

# --------------------------------------------------------
# Quantum vs Classical Attack Simulation (Visualization)
# --------------------------------------------------------

def map_costs(scheme, param):
    """Map each scheme to classical and quantum attack complexity constants."""
    if scheme == "RSA":
        Cc = param ** 3
        Cq = (param ** 2) * np.log2(param)
    elif scheme == "ECC":
        Cc = param ** 2.5
        Cq = param ** 1.3
    elif scheme == "LWE":
        Cc = param ** 2.8
        Cq = param ** 2.4
    elif scheme == "IDN-LWE":
        Cc = param ** 2.9
        Cq = param ** 2.7
    else:
        Cc = param ** 2.5
        Cq = param ** 2.0
    return Cc, Cq


def attack_success(time_array, complexity):
    """Simulate attack success probability as sigmoid function of time/complexity."""
    k = 5.0 / complexity ** 0.3
    return 1 / (1 + np.exp(-k * (time_array - complexity ** 0.5)))


# --------------------------------------------------------
# Performance Data Access
# --------------------------------------------------------

def get_perf_data():
    """Expose the performance log as a numpy-friendly structure."""
    import pandas as pd
    if not idn_lwe.perf_log:
        return pd.DataFrame(columns=["action", "scheme", "time_ms", "timestamp"])
    df = pd.DataFrame(idn_lwe.perf_log)
    return df
