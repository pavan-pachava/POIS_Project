"""PA#10: Educational HMAC implementation over toy hash compression."""

from backend.core.utils.bit_utils import hex_to_bytes, normalize_hex, text_to_bytes


IV = 0x12345678
MOD = 2**32
BLOCK_BYTES = 64


def _toy_hash_bytes(data: bytes) -> str:
    state = IV
    for byte in data:
        state = ((state ^ byte) * 16777619) % MOD
    return f"{state:08x}"


def toy_hmac(key_hex: str, message: str) -> dict:
    """Compute HMAC using toy hash and standard ipad/opad structure."""
    raw_key = hex_to_bytes(normalize_hex(key_hex))
    msg_bytes = text_to_bytes(message)
    steps = [f"Original key length = {len(raw_key)} bytes"]

    if len(raw_key) > BLOCK_BYTES:
        hashed = bytes.fromhex(_toy_hash_bytes(raw_key))
        steps.append(f"Key > block size, hash key -> {hashed.hex()}")
        raw_key = hashed

    if len(raw_key) < BLOCK_BYTES:
        raw_key = raw_key + b"\x00" * (BLOCK_BYTES - len(raw_key))
        steps.append(f"Pad key with zeros to {BLOCK_BYTES} bytes")

    ipad = bytes([0x36] * BLOCK_BYTES)
    opad = bytes([0x5C] * BLOCK_BYTES)
    k_ipad = bytes(a ^ b for a, b in zip(raw_key, ipad))
    k_opad = bytes(a ^ b for a, b in zip(raw_key, opad))

    inner_input = k_ipad + msg_bytes
    inner_digest = _toy_hash_bytes(inner_input)
    outer_input = k_opad + bytes.fromhex(inner_digest)
    tag = _toy_hash_bytes(outer_input)

    steps.extend(
        [
            f"Inner hash = H((K xor ipad) || m) = {inner_digest}",
            f"Outer hash = H((K xor opad) || inner) = {tag}",
        ]
    )

    return {
        "result": {
            "tag": tag,
            "inner_digest": inner_digest,
        },
        "steps": steps,
    }


def verify_toy_hmac(key_hex: str, message: str, tag_hex: str) -> dict:
    computed = toy_hmac(key_hex, message)
    expected = computed["result"]["tag"].lower()
    valid = expected == tag_hex.lower()
    return {
        "result": {
            "valid": valid,
            "expected": expected,
            "provided": tag_hex.lower(),
        },
        "steps": [*computed["steps"], f"Verification result = {valid}"],
    }


def crhf_to_mac_via_hmac(key_hex: str, message: str) -> dict:
    """PA#10 forward bridge witness: CRHF => MAC via HMAC construction."""
    out = toy_hmac(key_hex, message)
    return {
        "result": {
            "tag": out["result"]["tag"],
            "construction": "HMAC over compression-based hash",
        },
        "steps": [
            "Forward bridge (PA#10): use CRHF-style hash inside HMAC to realize a MAC.",
            *out["steps"],
        ],
    }


def mac_to_crhf_via_hmac(key_hex: str, cv: str, block: str) -> dict:
    """PA#10 backward bridge witness: MAC => CRHF via keyed-compression transform."""
    message = f"{cv}|{block}"
    out = toy_hmac(key_hex, message)
    return {
        "result": {
            "compression_output": out["result"]["tag"],
            "input": message,
            "construction": "h'(cv,block)=HMAC_k(cv||block)",
        },
        "steps": [
            "Backward bridge (PA#10): derive a compression primitive from MAC/HMAC.",
            "Define h'(cv, block)=HMAC_k(cv||block).",
            *out["steps"],
        ],
    }
