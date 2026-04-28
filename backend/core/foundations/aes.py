"""Toy AES foundation wrapper exposing OWF/PRF/PRP-style interfaces.

This is a pedagogical placeholder and not real AES.
"""

from backend.core.pa2_prf.ggm_prf import simple_prf
from backend.core.utils.bit_utils import int_to_hex


class AESFoundation:
    """Foundation adapter for AES-based route in the explorer."""

    name = "AES"

    def as_owf(self, seed_hex: str) -> dict:
        value = simple_prf(seed_hex, "0")["output"]
        return {"value": value, "steps": ["Use toy AES-as-PRF on input 0 for OWF view."]}

    def as_prf(self, key_hex: str, query_bits: str) -> dict:
        return simple_prf(key_hex, query_bits)

    def as_prp(self, key_hex: str, block_hex: str) -> dict:
        block_int = int(block_hex or "0", 16)
        key_int = int(key_hex or "0", 16)
        out = (block_int ^ key_int) & 0xFFFFFFFF
        return {
            "output": int_to_hex(out, min_bytes=4),
            "steps": ["Toy PRP: output = block XOR key (32-bit)."],
        }
