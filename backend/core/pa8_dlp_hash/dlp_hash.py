"""PA#8: Educational DLP-based hash function."""

from backend.core.utils.bit_utils import text_to_bytes
from backend.core.utils.math_utils import mod_exp


DEFAULT_G = 5
DEFAULT_P = 2147483647


def dlp_hash(message: str, g: int = DEFAULT_G, p: int = DEFAULT_P) -> dict:
    """Hash a message by mapping bytes to a DLP exponent."""
    data = text_to_bytes(message)
    exponent = 0
    steps = [f"Parameters: g={g}, p={p}"]

    for index, byte in enumerate(data, start=1):
        exponent = (exponent * 257 + byte) % (p - 1)
        steps.append(f"Byte {index}: exponent = (prev*257 + {byte}) mod (p-1) = {exponent}")

    digest_value = mod_exp(g, exponent, p)
    digest_hex = f"{digest_value:08x}"
    steps.append(f"Digest = g^exponent mod p = {digest_value} (hex {digest_hex})")

    return {
        "result": {
            "digest": digest_hex,
            "exponent": exponent,
        },
        "steps": steps,
    }
