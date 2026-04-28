"""PA#5: Toy CBC-MAC for variable-length messages."""

from backend.core.pa2_prf.ggm_prf import simple_prf
from backend.core.utils.bit_utils import bytes_to_hex, text_to_bytes, xor_bytes


BLOCK_BYTES = 4


def _apply_iso_padding(data: bytes, block_bytes: int = BLOCK_BYTES) -> bytes:
    """Apply ISO-style 0x80...00 padding to avoid variable-length ambiguity."""
    with_marker = data + b"\x80"
    remainder = len(with_marker) % block_bytes
    if remainder == 0:
        return with_marker
    return with_marker + (b"\x00" * (block_bytes - remainder))


def cbc_mac(key_hex: str, message: str, block_bytes: int = BLOCK_BYTES) -> dict:
    """Compute CBC-MAC tag by chaining PRF over message blocks."""
    raw = text_to_bytes(message)
    padded = _apply_iso_padding(raw, block_bytes=block_bytes)
    blocks = [padded[i : i + block_bytes] for i in range(0, len(padded), block_bytes)]

    state = b"\x00" * block_bytes
    steps = [
        f"Message bytes (hex) = {bytes_to_hex(raw)}",
        f"Padded bytes (hex) = {bytes_to_hex(padded)}",
        f"Block size = {block_bytes} bytes",
    ]

    for index, block in enumerate(blocks, start=1):
        mixed = xor_bytes(state, block)
        mixed_bits = "".join(f"{byte:08b}" for byte in mixed)
        prf_out = simple_prf(key_hex, mixed_bits)["output"]
        prf_bytes = bytes.fromhex(prf_out)
        if len(prf_bytes) < block_bytes:
            raise ValueError(
                f"PRF output length ({len(prf_bytes)} bytes) must be at least CBC-MAC block size ({block_bytes} bytes). "
                "Use a PRF with larger output or reduce the configured block size."
            )
        state = prf_bytes[:block_bytes]
        steps.append(
            f"Block {index}: state XOR block = {bytes_to_hex(mixed)}, PRF -> {prf_out}, next state = {bytes_to_hex(state)}"
        )

    tag = bytes_to_hex(state)
    steps.append(f"CBC-MAC tag = {tag}")
    return {"tag": tag, "steps": steps, "block_count": len(blocks)}


def verify_cbc_mac(key_hex: str, message: str, tag_hex: str, block_bytes: int = BLOCK_BYTES) -> dict:
    """Verify CBC-MAC tag by recomputing and comparing."""
    computed = cbc_mac(key_hex, message, block_bytes=block_bytes)
    expected = computed["tag"].lower()
    provided = tag_hex.lower()
    valid = expected == provided
    return {
        "valid": valid,
        "expected_tag": expected,
        "provided_tag": provided,
        "steps": [*computed["steps"], f"Verification result = {valid}"],
    }
