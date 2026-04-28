"""PA#3: Toy decryption for the CPA encryption scheme."""

from backend.core.pa3_cpa_enc.enc import _keystream_from_prf
from backend.core.utils.bit_utils import hex_to_bytes, int_to_hex, xor_bytes


def cpa_decrypt(key_hex: str, nonce_hex: str, ciphertext_hex: str) -> dict:
    """Decrypt ciphertext and return plaintext bytes and steps."""
    nonce = int(nonce_hex, 16)
    ciphertext_clean = ciphertext_hex.strip()
    cipher = b"" if not ciphertext_clean else hex_to_bytes(ciphertext_clean)
    stream = _keystream_from_prf(key_hex, nonce, len(cipher))
    plain = xor_bytes(cipher, stream)

    return {
        "r": int_to_hex(nonce, min_bytes=4),
        "plaintext": plain.decode("utf-8", errors="replace"),
        "steps": [
            f"Nonce r = {nonce}",
            f"Recomputed keystream length = {len(stream)}",
            "Plaintext = Ciphertext XOR Keystream",
        ],
    }
