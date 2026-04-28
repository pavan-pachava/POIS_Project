"""PA#15: RSA/ElGamal signatures, EUF-CMA demo, and raw-RSA forgery demo."""

import hashlib
import random

from backend.core.pa12_rsa.rsa import modexp, rsa_keygen
from backend.core.pa16_elgamal.elgamal import elgamal_keygen


def _hash_to_int(message: str, modulus: int) -> int:
    digest = hashlib.sha256(message.encode("utf-8")).digest()
    return int.from_bytes(digest, "big") % modulus


def rsa_sign(message: str, n: int, d: int) -> dict:
    h = _hash_to_int(message, n)
    sig = modexp(h, d, n)
    return {
        "result": {"signature": sig, "hash": h},
        "steps": [f"h=H(m) mod n={h}", f"sigma=h^d mod n={sig}"],
    }


def rsa_verify(message: str, signature: int, n: int, e: int) -> dict:
    h = _hash_to_int(message, n)
    recovered = modexp(signature, e, n)
    valid = recovered == h
    return {
        "result": {"valid": valid, "expected_hash": h, "recovered": recovered},
        "steps": [f"expected hash={h}", f"sigma^e mod n={recovered}", f"valid={valid}"],
    }


def raw_rsa_sign(message_int: int, n: int, d: int) -> int:
    return modexp(message_int % n, d, n)


def raw_rsa_forgery_demo(n: int, e: int, d: int, m1: int, m2: int) -> dict:
    """Demonstrate multiplicative forgery if raw RSA signs message directly."""
    s1 = raw_rsa_sign(m1, n, d)
    s2 = raw_rsa_sign(m2, n, d)
    forged_m = (m1 * m2) % n
    forged_sig = (s1 * s2) % n
    verifies = modexp(forged_sig, e, n) == forged_m
    return {
        "result": {
            "m1": m1,
            "m2": m2,
            "s1": s1,
            "s2": s2,
            "forged_message": forged_m,
            "forged_signature": forged_sig,
            "forgery_valid": verifies,
        },
        "steps": [
            "Raw RSA is multiplicative: sig(m1*m2)=sig(m1)*sig(m2) mod n",
            f"forgery_valid={verifies}",
        ],
    }


def euf_cma_game_demo(max_queries: int = 50) -> dict:
    """Simple EUF-CMA game with random-message adversary."""
    keys = rsa_keygen(bits=64)["result"]
    n = keys["public_key"]["n"]
    e = keys["public_key"]["e"]
    d = keys["private_key"]["d"]

    signed: dict[str, int] = {}
    for i in range(max_queries):
        msg = f"query-{i}-{random.randrange(1 << 30)}"
        signed[msg] = rsa_sign(msg, n, d)["result"]["signature"]

    forge_msg = "new-forge-target"
    forge_sig = random.randrange(2, n - 1)
    valid = rsa_verify(forge_msg, forge_sig, n, e)["result"]["valid"]

    return {
        "result": {
            "queries": max_queries,
            "forged_message": forge_msg,
            "forged_signature": forge_sig,
            "forgery_success": valid,
        },
        "steps": [
            f"Signing oracle answered {max_queries} queries",
            "Adversary attempts random forgery on unseen message",
            f"Forgery success={valid}",
        ],
    }


def elgamal_sign(message: str, p: int, g: int, x: int) -> dict:
    h = _hash_to_int(message, p - 1)
    while True:
        k = random.randrange(2, p - 2)
        if math_gcd(k, p - 1) == 1:
            break

    r = modexp(g, k, p)
    k_inv = mod_inverse(k, p - 1)
    s = ((h - x * r) * k_inv) % (p - 1)
    return {
        "result": {"signature": {"r": r, "s": s}, "hash": h},
        "steps": [f"h={h}", f"r={r}", f"s={s}"],
    }


def elgamal_verify(message: str, r: int, s: int, p: int, g: int, y: int) -> dict:
    if not (0 < r < p):
        return {"result": {"valid": False}, "steps": ["Invalid r range"]}
    h = _hash_to_int(message, p - 1)
    left = modexp(g, h, p)
    right = (modexp(y, r, p) * modexp(r, s, p)) % p
    valid = left == right
    return {
        "result": {"valid": valid, "left": left, "right": right},
        "steps": [f"left={left}", f"right={right}", f"valid={valid}"],
    }


def sample_elgamal_keys(bits: int = 16) -> dict:
    return elgamal_keygen(bits)


def math_gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def mod_inverse(a: int, n: int) -> int:
    t, new_t = 0, 1
    r, new_r = n, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r != 1:
        raise ValueError("Inverse does not exist")
    return t % n
