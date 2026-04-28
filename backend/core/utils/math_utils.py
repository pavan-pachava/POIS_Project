"""Math utility helpers for toy cryptographic primitives."""


def mod_exp(base: int, exponent: int, modulus: int) -> int:
    """Compute modular exponentiation efficiently."""
    return pow(base, exponent, modulus)
