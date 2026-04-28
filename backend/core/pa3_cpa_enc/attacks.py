"""Educational attack simulations for the toy CPA encryption scheme."""

import logging

from backend.core.pa3_cpa_enc.enc import _keystream_from_prf
from backend.core.utils.bit_utils import bytes_to_hex, int_to_hex, text_to_bytes, xor_bytes
from backend.core.utils.random_utils import secure_randbelow

logger = logging.getLogger(__name__)


def _encrypt_with_fixed_nonce(key_hex: str, message: str, nonce: int) -> tuple[str, bytes]:
    message_bytes = text_to_bytes(message)
    stream = _keystream_from_prf(key_hex, nonce, len(message_bytes))
    ciphertext = xor_bytes(message_bytes, stream)
    return bytes_to_hex(ciphertext), message_bytes


def simulate_cpa_attack(
    key_hex: str,
    m0: str,
    m1: str,
    challenge_bit: int | None = 1,
    reused_nonce: int = 7,
    trials: int = 1,
) -> dict:
    """Simulate a chosen-plaintext attack when challenge encryption reuses a fixed nonce."""
    if challenge_bit is not None and challenge_bit not in (0, 1):
        raise ValueError("challenge_bit must be 0 or 1 when provided")
    if trials < 1:
        raise ValueError("trials must be >= 1")

    c0_hex, _ = _encrypt_with_fixed_nonce(key_hex, m0, reused_nonce)
    c1_hex, _ = _encrypt_with_fixed_nonce(key_hex, m1, reused_nonce)

    successful_trials = 0
    challenge_hex = ""
    selected_bit = challenge_bit if challenge_bit is not None else secure_randbelow(2)
    guess = -1

    for index in range(trials):
        bit = selected_bit if (challenge_bit is not None and index == 0) else secure_randbelow(2)
        challenge_message = m0 if bit == 0 else m1
        trial_challenge_hex, _ = _encrypt_with_fixed_nonce(key_hex, challenge_message, reused_nonce)
        trial_guess = 0 if trial_challenge_hex == c0_hex else 1 if trial_challenge_hex == c1_hex else -1
        if trial_guess == bit:
            successful_trials += 1
        if index == 0:
            selected_bit = bit
            challenge_hex = trial_challenge_hex
            guess = trial_guess

    success_rate = successful_trials / trials
    success = guess == selected_bit

    logger.info("CPA attack simulation: success=%s guess=%s bit=%s nonce=%s trials=%s", success, guess, selected_bit, reused_nonce, trials)

    return {
        "result": {
            "success": success,
            "challenge_bit": selected_bit,
            "adversary_guess": guess,
            "challenge_ciphertext": challenge_hex,
            "nonce_hex": int_to_hex(reused_nonce, min_bytes=4),
            "success_rate": success_rate,
            "trials": trials,
        },
        "steps": [
            f"Encrypt m0 with reused nonce -> c0={c0_hex}",
            f"Encrypt m1 with reused nonce -> c1={c1_hex}",
            f"Challenge ciphertext c* = Enc(m_b) with b={selected_bit} -> {challenge_hex}",
            f"Adversary compares c* to (c0, c1) and guesses {guess}",
            f"Attack success = {success}; success rate across {trials} trial(s) = {success_rate:.2f}",
        ],
    }


def simulate_nonce_reuse_attack(
    key_hex: str,
    known_plaintext: str,
    target_plaintext: str,
    reused_nonce: int = 7,
) -> dict:
    """Demonstrate plaintext recovery when the same nonce is reused."""
    c1_hex, p1 = _encrypt_with_fixed_nonce(key_hex, known_plaintext, reused_nonce)
    c2_hex, p2 = _encrypt_with_fixed_nonce(key_hex, target_plaintext, reused_nonce)

    c1 = bytes.fromhex(c1_hex)
    c2 = bytes.fromhex(c2_hex)
    limit = min(len(c1), len(c2), len(p1))

    recovered_prefix = xor_bytes(xor_bytes(c1[:limit], c2[:limit]), p1[:limit])
    target_prefix = p2[:limit]
    success = recovered_prefix == target_prefix

    logger.info(
        "Nonce reuse attack simulation: success=%s nonce=%s recovered_len=%s",
        success,
        reused_nonce,
        len(recovered_prefix),
    )

    return {
        "result": {
            "success": success,
            "nonce_hex": int_to_hex(reused_nonce, min_bytes=4),
            "ciphertext_1": c1_hex,
            "ciphertext_2": c2_hex,
            "recovered_target_prefix": recovered_prefix.decode("utf-8", errors="replace"),
            "actual_target_prefix": target_prefix.decode("utf-8", errors="replace"),
        },
        "steps": [
            f"Reuse nonce r={reused_nonce} for two encryptions.",
            f"Compute c1 xor c2 = xor(m1, m2) (hex {(xor_bytes(c1[:limit], c2[:limit])).hex()})",
            "Recover target prefix via (c1 xor c2 xor known_plaintext_prefix).",
            f"Recovered prefix = {recovered_prefix!r}",
            f"Attack success = {success}",
        ],
    }


def simulate_malleability_attack(
    key_hex: str,
    plaintext: str,
    flip_mask_hex: str = "01",
    reused_nonce: int = 9,
) -> dict:
    """Demonstrate ciphertext malleability by controlled bit flipping."""
    if not plaintext:
        raise ValueError("plaintext must be non-empty")

    ciphertext_hex, plain = _encrypt_with_fixed_nonce(key_hex, plaintext, reused_nonce)
    ciphertext = bytes.fromhex(ciphertext_hex)
    mask_bytes = bytes.fromhex(flip_mask_hex.strip().replace("0x", "") or "00")
    if len(mask_bytes) == 0:
        mask_bytes = b"\x00"

    repeated_mask = (mask_bytes * ((len(ciphertext) // len(mask_bytes)) + 1))[: len(ciphertext)]
    tampered_ciphertext = xor_bytes(ciphertext, repeated_mask)
    stream = _keystream_from_prf(key_hex, reused_nonce, len(ciphertext))
    tampered_plaintext = xor_bytes(tampered_ciphertext, stream)

    flips = xor_bytes(plain, tampered_plaintext)
    return {
        "result": {
            "nonce_hex": int_to_hex(reused_nonce, min_bytes=4),
            "original_ciphertext": bytes_to_hex(ciphertext),
            "tampered_ciphertext": bytes_to_hex(tampered_ciphertext),
            "original_plaintext": plain.decode("utf-8", errors="replace"),
            "modified_plaintext": tampered_plaintext.decode("utf-8", errors="replace"),
            "applied_flip_mask_hex": bytes_to_hex(repeated_mask),
            "plaintext_difference_hex": bytes_to_hex(flips),
        },
        "steps": [
            "Encrypt plaintext under stream-based CPA encryption.",
            "Adversary flips chosen bits in ciphertext without knowing the key.",
            "On decryption, the same bit-flips appear in plaintext (malleability).",
            f"Observed plaintext xor-delta = {bytes_to_hex(flips)}",
        ],
    }
