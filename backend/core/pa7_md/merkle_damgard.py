"""PA#7: Toy Merkle-Damgård hash with MD-strengthening padding."""

from backend.core.utils.bit_utils import text_to_bytes


IV = 0x12345678
MOD = 2**32
BLOCK_SIZE_BITS = 512
BLOCK_SIZE_BYTES = BLOCK_SIZE_BITS // 8
LENGTH_FIELD_BITS = 64
LENGTH_FIELD_BYTES = LENGTH_FIELD_BITS // 8


def _md_strengthen(message_bytes: bytes) -> bytes:
    """Apply Merkle-Damgård strengthening: 1-bit, zero padding, 64-bit length."""
    original_len_bits = len(message_bytes) * 8
    padded = bytearray(message_bytes)
    padded.append(0x80)  # append bit '1' then seven '0' bits

    target_mod = BLOCK_SIZE_BITS - LENGTH_FIELD_BITS
    while ((len(padded) * 8) % BLOCK_SIZE_BITS) != target_mod:
        padded.append(0x00)

    padded.extend((original_len_bits % (1 << LENGTH_FIELD_BITS)).to_bytes(LENGTH_FIELD_BYTES, "big"))
    return bytes(padded)


def _compress(state: int, block: bytes) -> int:
    """Toy compression function over one full block."""
    next_state = state
    for idx, byte in enumerate(block, start=1):
        next_state = ((next_state ^ byte) * 16777619) % MOD
        next_state = (next_state + idx) % MOD
    return next_state


def toy_hash(message: str) -> dict:
    """Compute toy Merkle-Damgård hash and return digest + chaining trace."""
    data = text_to_bytes(message)
    padded = _md_strengthen(data)
    blocks = [padded[i : i + BLOCK_SIZE_BYTES] for i in range(0, len(padded), BLOCK_SIZE_BYTES)]

    state = IV
    chaining_values = [f"{state:08x}"]
    steps = [
        f"Initial IV z0 = {IV:#010x}",
        f"Original message length = {len(data) * 8} bits",
        f"Padded length = {len(padded) * 8} bits ({len(blocks)} block(s) of {BLOCK_SIZE_BITS} bits)",
    ]

    for idx, block in enumerate(blocks, start=1):
        prev_state = state
        state = _compress(state, block)
        chaining_values.append(f"{state:08x}")
        steps.append(
            f"Block {idx}: z{idx - 1}={prev_state:#010x}, M{idx}={block.hex()}, z{idx}={state:#010x}"
        )

    digest = f"{state:08x}"
    steps.append(f"Digest = {digest}")
    return {"digest": digest, "chaining_values": chaining_values, "steps": steps}
