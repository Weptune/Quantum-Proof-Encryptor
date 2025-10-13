# core/ml_attack.py
"""
ML Attack scaffold: dataset builder + simple model baseline
This file provides dataset creation functions to turn many ciphertexts into
training examples; real models go in separate notebooks / scripts.
"""
import numpy as np

def build_dataset_from_ciphertexts(ciphertexts, secrets, feature_fn):
    """
    ciphertexts: list of ciphertext objects (each contains A and C)
    secrets: ground-truth secret vector (reused across many ciphertexts)
    feature_fn: function(ct) -> feature vector (1D array)
    returns X, y (numpy arrays)
    """
    X = np.array([feature_fn(ct) for ct in ciphertexts])
    y = np.array(secrets)  # adapt this depending on label type
    return X, y

def example_feature_fn(ct, q=4093):
    # Simple flattened A plus scalar C (centered)
    A = np.array(ct["A"], dtype=float)
    C = float(ct["C"]) if isinstance(ct["C"], (int, float)) else float(0)
    return np.concatenate([A, np.array([C])])
