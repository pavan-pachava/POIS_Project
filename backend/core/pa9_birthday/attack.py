"""PA#9: Educational birthday attack against truncated hash outputs."""

import logging
import random
import string

from backend.core.pa7_md.merkle_damgard import toy_hash


ALPHABET = string.ascii_letters + string.digits
SUPPORTED_TRUNCATE_BITS = {8, 10, 12, 14, 16}
logger = logging.getLogger(__name__)


def _random_alphanumeric_string(length: int = 8) -> str:
    return "".join(random.choice(ALPHABET) for _ in range(length))


def birthday_collision_attack(truncate_bits: int = 12, max_trials: int = 10000) -> dict:
    """Find a collision on a truncated toy hash output."""
    if truncate_bits not in SUPPORTED_TRUNCATE_BITS:
        supported_values = ", ".join(str(bits) for bits in sorted(SUPPORTED_TRUNCATE_BITS))
        raise ValueError(f"truncate_bits must be one of {{{supported_values}}}")

    seen: dict[str, str] = {}
    steps = [f"Target collision size: first {truncate_bits} bits"]

    for trial in range(1, max_trials + 1):
        msg = _random_alphanumeric_string()
        digest = toy_hash(msg)["digest"]
        digest_bits = f"{int(digest, 16):0{len(digest) * 4}b}"
        bucket = digest_bits[:truncate_bits]

        if bucket in seen and seen[bucket] != msg:
            steps.append(f"Collision found at attempt {trial}: '{seen[bucket]}' and '{msg}' -> {bucket}")
            logger.info(
                "Birthday attack collision found: truncate_bits=%s trials=%s digest=%s",
                truncate_bits,
                trial,
                bucket,
            )
            return {
                "result": {
                    "found": True,
                    "attempts": trial,
                    "colliding_input_1": seen[bucket],
                    "colliding_input_2": msg,
                    "truncated_hash": bucket,
                },
                "steps": steps,
            }

        if trial <= 10 or trial % 500 == 0:
            steps.append(f"Attempt {trial}: msg='{msg}', digest={digest}, n-bit-prefix={bucket}")
        seen[bucket] = msg

    steps.append("No collision found within max_trials.")
    logger.info(
        "Birthday attack finished without collision: truncate_bits=%s max_trials=%s",
        truncate_bits,
        max_trials,
    )
    return {
        "result": {
            "found": False,
            "attempts": max_trials,
        },
        "steps": steps,
    }
