"""PA#4: Educational OFB mode using toy PRF feedback."""

from backend.core.pa2_prf.ggm_prf import simple_prf
from backend.core.utils.bit_utils import bytes_to_hex, hex_to_bytes, xor_bytes

BLOCK_BYTES = 4


def ofb_crypt(key_hex: str, data: bytes, iv_hex: str) -> dict:
    """Encrypt/decrypt bytes in OFB mode (same operation both ways)."""
    feedback = hex_to_bytes(iv_hex)
    if len(feedback) != BLOCK_BYTES:
        raise ValueError(f"IV must be {BLOCK_BYTES} bytes")

    out_blocks = []
    blocks = []
    steps = [f"OFB IV = {iv_hex.lower()}", f"Input data hex = {bytes_to_hex(data)}"]

    for index in range(0, len(data), BLOCK_BYTES):
        block = data[index : index + BLOCK_BYTES]
        query = "".join(f"{byte:08b}" for byte in feedback)
        feedback = bytes.fromhex(simple_prf(key_hex, query)["output"])[:BLOCK_BYTES]
        out_block = xor_bytes(block, feedback[: len(block)])
        out_blocks.append(out_block)
        blocks.append(
            {
                "block": index // BLOCK_BYTES,
                "input": bytes_to_hex(block),
                "keystream": bytes_to_hex(feedback[: len(block)]),
                "output": bytes_to_hex(out_block),
            }
        )
        steps.append(
            f"Block {index // BLOCK_BYTES}: feedback->keystream={bytes_to_hex(feedback)}, output={bytes_to_hex(out_block)}"
        )

    return {
        "result": {
            "mode": "OFB",
            "iv": iv_hex.lower(),
            "output_hex": bytes_to_hex(b"".join(out_blocks)),
            "blocks": blocks,
        },
        "steps": steps,
    }
