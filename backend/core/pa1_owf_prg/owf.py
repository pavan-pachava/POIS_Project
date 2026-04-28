"""PA#1: Toy one-way function based on modular exponentiation."""

from backend.core.utils.math_utils import mod_exp


def simple_owf(x: int, g: int = 5, p: int = 2147483647) -> dict:
    """Compute y = g^x mod p and return value + steps."""
    y = mod_exp(g, x, p)
    steps = [
        f"Input x = {x}",
        f"Parameters g = {g}, p = {p}",
        f"Compute y = g^x mod p = {y}",
    ]
    return {"output": y, "steps": steps}
