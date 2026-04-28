"""Random utility helpers."""

import secrets


def secure_randbelow(limit: int) -> int:
    """Return a random integer in [0, limit)."""
    if limit <= 0:
        raise ValueError("limit must be positive")
    return secrets.randbelow(limit)
