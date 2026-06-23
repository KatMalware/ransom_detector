"""
Ransomware Detection System — Shannon Entropy Calculator
Detects encrypted / high-randomness files that indicate ransomware activity.
"""

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of raw bytes.
    Returns a value between 0.0 (perfectly uniform) and 8.0 (maximum randomness).
    Encrypted data typically scores 7.8 – 8.0.
    """
    if not data:
        return 0.0

    length = len(data)
    freq = Counter(data)

    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def file_entropy(filepath: str) -> float:
    """Read a file and return its Shannon entropy."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        return shannon_entropy(data)
    except (IOError, OSError):
        return 0.0


def is_likely_encrypted(filepath: str, threshold: float = 7.5) -> bool:
    """
    Quick check: does a file's entropy suggest it has been encrypted?

    Normal document files  → entropy ~3.0 – 6.5
    Compressed archives    → entropy ~7.0 – 7.9
    Encrypted (ransomware) → entropy ~7.8 – 8.0
    """
    return file_entropy(filepath) >= threshold


def entropy_delta(old_entropy: float, new_entropy: float) -> float:
    """Return the increase in entropy (negative means entropy dropped)."""
    return new_entropy - old_entropy
