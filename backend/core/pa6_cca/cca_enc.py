"""PA#6: CCA-secure toy encryption via Encrypt-then-MAC."""

from backend.core.pa3_cpa_enc.dec import cpa_decrypt
from backend.core.pa3_cpa_enc.enc import cpa_encrypt
from backend.core.pa5_mac.prf_mac import prf_mac, verify_prf_mac


def cca_encrypt_then_mac(key_enc: str, key_mac: str, message: str) -> dict:
    """Encrypt message then authenticate ciphertext bundle."""
    enc_result = cpa_encrypt(key_enc, message)
    bundle = f"{enc_result['r']}:{enc_result['ciphertext']}"
    mac_result = prf_mac(key_mac, bundle)

    steps = [
        "Step 1: Encrypt plaintext with CPA scheme.",
        *enc_result["steps"],
        f"Step 2: Build authenticated bundle = {bundle}",
        "Step 3: Compute MAC tag over bundle.",
        *mac_result["steps"],
    ]

    return {
        "result": {
            "r": enc_result["r"],
            "ciphertext": enc_result["ciphertext"],
            "tag": mac_result["tag"],
        },
        "steps": steps,
    }


def cca_decrypt_then_verify(key_enc: str, key_mac: str, r_hex: str, ciphertext_hex: str, tag_hex: str) -> dict:
    """Verify MAC first, then decrypt if valid."""
    bundle = f"{r_hex}:{ciphertext_hex}"
    verification = verify_prf_mac(key_mac, bundle, tag_hex)
    steps = [
        f"Received bundle = {bundle}",
        "Verify MAC tag before decryption (Encrypt-then-MAC).",
        *verification["steps"],
    ]

    if not verification["valid"]:
        steps.append("Verification failed: reject ciphertext (CCA-safe behavior).")
        return {"result": {"accepted": False, "plaintext": None}, "steps": steps}

    dec_result = cpa_decrypt(key_enc, r_hex, ciphertext_hex)
    steps.extend(["Verification passed: decrypt ciphertext.", *dec_result["steps"]])
    return {
        "result": {
            "accepted": True,
            "plaintext": dec_result["plaintext"],
        },
        "steps": steps,
    }
