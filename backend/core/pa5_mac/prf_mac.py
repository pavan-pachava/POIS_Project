"""PA#5: Toy PRF-based MAC."""

from backend.core.pa2_prf.ggm_prf import simple_prf
from backend.core.utils.bit_utils import bytes_to_bits, text_to_bytes


def prf_mac(key_hex: str, message: str) -> dict:
    """Compute a MAC tag as PRF_k(bits(message))."""
    message_bits = bytes_to_bits(text_to_bytes(message)) or "0"
    prf_result = simple_prf(key_hex, message_bits)
    steps = [
        f"Message bits = {message_bits}",
        "Tag = PRF_k(message_bits)",
        *prf_result["steps"],
    ]
    return {"tag": prf_result["output"], "steps": steps}


def verify_prf_mac(key_hex: str, message: str, tag_hex: str) -> dict:
    """Verify PRF-MAC tag by recomputing and comparing."""
    computed = prf_mac(key_hex, message)
    expected = computed["tag"].lower()
    provided = tag_hex.lower()
    valid = expected == provided
    return {
        "valid": valid,
        "expected_tag": expected,
        "provided_tag": provided,
        "steps": [*computed["steps"], f"Verification result = {valid}"],
    }
