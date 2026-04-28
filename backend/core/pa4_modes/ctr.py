"""PA#4: Educational CTR mode using toy PRF keystream blocks."""

from backend.core.pa2_prf.ggm_prf import simple_prf
from backend.core.utils.bit_utils import bytes_to_hex, hex_to_bytes, int_to_hex, xor_bytes

BLOCK_BYTES = 4


def ctr_crypt(key_hex: str, data: bytes, nonce_hex: str) -> dict:
    """Encrypt/decrypt bytes in CTR mode (same operation both ways)."""
    nonce = int(nonce_hex, 16)
    steps = [
        f"CTR nonce = {nonce} (hex {nonce_hex.lower()})",
        f"Input data hex = {bytes_to_hex(data)}",
    ]

    out_blocks = []
    block_view = []
    for index in range(0, len(data), BLOCK_BYTES):
        block = data[index : index + BLOCK_BYTES]
        counter = index // BLOCK_BYTES
        query = f"{nonce:032b}{counter:032b}"
        stream = bytes.fromhex(simple_prf(key_hex, query)["output"])[: len(block)]
        out_block = xor_bytes(block, stream)
        out_blocks.append(out_block)
        block_view.append(
            {
                "counter": counter,
                "input": bytes_to_hex(block),
                "keystream": bytes_to_hex(stream),
                "output": bytes_to_hex(out_block),
            }
        )
        steps.append(
            f"Block {counter}: stream=PRF_k(nonce||ctr)={bytes_to_hex(stream)}, output=input xor stream={bytes_to_hex(out_block)}"
        )

    output = b"".join(out_blocks)
    return {
        "result": {
            "mode": "CTR",
            "nonce": int_to_hex(nonce, min_bytes=4),
            "output_hex": bytes_to_hex(output),
            "blocks": block_view,
        },
        "steps": steps,
    }


def ctr_crypt_hex(key_hex: str, data_hex: str, nonce_hex: str) -> dict:
    """Hex wrapper around ctr_crypt."""
    return ctr_crypt(key_hex, hex_to_bytes(data_hex), nonce_hex)
