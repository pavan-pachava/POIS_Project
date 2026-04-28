"""PA#3: Toy CPA encryption using r and PRF-derived keystream."""

from backend.core.pa2_prf.ggm_prf import simple_prf
from backend.core.utils.bit_utils import bytes_to_hex, int_to_hex, text_to_bytes, xor_bytes
from backend.core.utils.random_utils import secure_randbelow


def _keystream_from_prf(key_hex: str, nonce: int, size: int) -> bytes:
    """Generate a byte keystream by querying PRF on nonce/counter values."""
    blocks = []
    counter = 0
    while len(b"".join(blocks)) < size:
        query = f"{nonce:032b}{counter:032b}"
        prf_out = simple_prf(key_hex, query)["output"]
        blocks.append(bytes.fromhex(prf_out))
        counter += 1
    return b"".join(blocks)[:size]


def cpa_encrypt(key_hex: str, message: str) -> dict:
    """Encrypt UTF-8 message with random nonce and XOR keystream."""
    message_bytes = text_to_bytes(message)
    nonce = secure_randbelow(2**31 - 1)
    stream = _keystream_from_prf(key_hex, nonce, len(message_bytes))
    cipher_bytes = xor_bytes(message_bytes, stream)

    steps = [
        f"Message bytes (hex) = {bytes_to_hex(message_bytes)}",
        f"Random nonce r = {nonce} (hex {int_to_hex(nonce, min_bytes=4)})",
        f"Keystream = {bytes_to_hex(stream)}",
        "Ciphertext = Message XOR Keystream",
    ]

    return {
        "r": int_to_hex(nonce, min_bytes=4),
        "ciphertext": bytes_to_hex(cipher_bytes),
        "steps": steps,
    }
