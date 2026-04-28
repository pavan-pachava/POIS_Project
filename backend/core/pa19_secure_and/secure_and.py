"""PA#19: Secure boolean gates built atop PA#18 OT."""

import random

from backend.core.pa18_ot.ot import bellare_micali_ot


def _validate_bit(value: int, name: str) -> None:
    if value not in (0, 1):
        raise ValueError(f"{name} must be a bit (0 or 1)")


def secure_and_from_ot(a_bit: int, b_bit: int) -> dict:
    """Compute AND using OT: sender messages are (0, a), receiver choice is b."""
    _validate_bit(a_bit, "a_bit")
    _validate_bit(b_bit, "b_bit")

    ot_result = bellare_micali_ot(m0=0, m1=a_bit, choice_bit=b_bit)
    and_bit = int(ot_result["result"]["received_message"]) & 1

    return {
        "result": {
            "a": a_bit,
            "b": b_bit,
            "and": and_bit,
        },
        "steps": [
            "Alice (sender) sets OT messages as (m0,m1)=(0,a).",
            "Bob (receiver) sets OT choice b.",
            *ot_result["steps"],
            f"Recovered OT message equals a AND b = {and_bit}",
        ],
    }


def secure_xor_gate(a_bit: int, b_bit: int) -> dict:
    """Compute XOR with additive sharing over Z2 (communication-light/free gate)."""
    _validate_bit(a_bit, "a_bit")
    _validate_bit(b_bit, "b_bit")

    r = random.randint(0, 1)
    alice_share = a_bit ^ r
    bob_share = b_bit ^ r
    xor_bit = alice_share ^ bob_share

    return {
        "result": {
            "a": a_bit,
            "b": b_bit,
            "xor": xor_bit,
            "alice_share": alice_share,
            "bob_share": bob_share,
        },
        "steps": [
            f"Sample random mask r={r}",
            f"Alice share: a xor r = {alice_share}",
            f"Bob share: b xor r = {bob_share}",
            f"Combine shares: xor={xor_bit}",
        ],
    }


def secure_not_gate(a_bit: int) -> dict:
    """Compute NOT locally (free gate)."""
    _validate_bit(a_bit, "a_bit")
    value = 1 - a_bit
    return {
        "result": {
            "a": a_bit,
            "not": value,
        },
        "steps": [
            f"Local bit flip: NOT({a_bit})={value}",
        ],
    }


def secure_and_gate(a_bit: int, b_bit: int) -> dict:
    """Backward-compatible PA#19 API for secure AND."""
    return secure_and_from_ot(a_bit=a_bit, b_bit=b_bit)
