"""DLP foundation wrapper exposing OWF/OWP-style interfaces."""

from backend.core.pa1_owf_prg.owf import simple_owf
from backend.core.utils.bit_utils import hex_to_int, int_to_hex


class DLPFoundation:
    """Foundation adapter for DLP-based route in the explorer."""

    name = "DLP"

    def as_owf(self, seed_hex: str, g: int = 5, p: int = 2147483647) -> dict:
        x = hex_to_int(seed_hex)
        result = simple_owf(x, g=g, p=p)
        return {
            "value": int_to_hex(result["output"], min_bytes=4),
            "steps": result["steps"],
        }

    def as_owp(self, seed_hex: str, g: int = 5, p: int = 2147483647) -> dict:
        return self.as_owf(seed_hex, g=g, p=p)
