"""PA#16: ElGamal PKC, malleability demo, and IND-CPA game."""

import random

from backend.core.pa11_dh.diffie_hellman import generate_safe_prime_group
from backend.core.pa13_miller_rabin.miller_rabin import modexp


def elgamal_keygen(bits: int = 16, g: int = 2) -> dict:
    """Generate ElGamal keys over PA#11-style safe-prime group."""
    group = generate_safe_prime_group(bits=max(bits, 12))["result"]
    p = group["p"]
    q = group["q"]
    generator = group["g"] if g == 2 else g
    x = random.randrange(1, q)
    y = modexp(generator, x, p)

    return {
        "result": {
            "public_key": {"p": p, "g": generator, "q": q, "y": y},
            "private_key": {"x": x},
        },
        "steps": [
            f"Generate safe-prime group p={p}, q={q}, g={generator}",
            f"Choose secret x in Z_q: x={x}",
            f"Compute y=g^x mod p={y}",
        ],
    }


def elgamal_encrypt(message_int: int, p: int, g: int, y: int) -> dict:
    """Encrypt integer message under ElGamal public key."""
    if not (0 <= message_int < p):
        raise ValueError("message_int must satisfy 0 <= m < p")
    k = random.randrange(2, p - 2)
    c1 = modexp(g, k, p)
    s = modexp(y, k, p)
    c2 = (message_int * s) % p

    return {
        "result": {"ciphertext": {"c1": c1, "c2": c2}},
        "steps": [
            f"Pick random k={k}",
            f"c1 = g^k mod p = {c1}",
            f"shared s = y^k mod p = {s}",
            f"c2 = m*s mod p = {c2}",
        ],
    }


def elgamal_decrypt(c1: int, c2: int, p: int, x: int) -> dict:
    """Decrypt ElGamal ciphertext."""
    s = modexp(c1, x, p)
    s_inv = modexp(s, p - 2, p)
    m = (c2 * s_inv) % p
    return {
        "result": {"plaintext": m},
        "steps": [
            f"shared s = c1^x mod p = {s}",
            f"s^-1 mod p = {s_inv}",
            f"m = c2*s^-1 mod p = {m}",
        ],
    }


def elgamal_malleability_attack(c1: int, c2: int, p: int) -> dict:
    """Construct (c1, 2*c2 mod p) to transform m -> 2m."""
    attacked = {"c1": c1, "c2": (2 * c2) % p}
    return {
        "result": {"modified_ciphertext": attacked},
        "steps": [
            "Given ciphertext (c1,c2), attacker outputs (c1,2*c2 mod p)",
            "Decryption maps m -> 2m mod p without knowing secret key",
        ],
    }


def elgamal_cpa_game(m0: int, m1: int, bits: int = 16, force_tiny_group: bool = False) -> dict:
    """Run simplified IND-CPA game for ElGamal."""
    key_bits = 10 if force_tiny_group else bits
    keys = elgamal_keygen(bits=key_bits)["result"]
    pk = keys["public_key"]
    x = keys["private_key"]["x"]

    b = random.randint(0, 1)
    challenge_message = m0 if b == 0 else m1
    c = elgamal_encrypt(challenge_message % pk["p"], pk["p"], pk["g"], pk["y"])["result"]["ciphertext"]

    # Baseline adversary: random guess. On tiny groups, brute-force discrete logs to do better.
    if force_tiny_group:
        # Toy distinguisher: decrypt with brute-forced x by checking g^guess=y.
        recovered_x = None
        for guess in range(1, pk.get("q", pk["p"] - 1)):
            if modexp(pk["g"], guess, pk["p"]) == pk["y"]:
                recovered_x = guess
                break
        if recovered_x is not None:
            recovered = elgamal_decrypt(c["c1"], c["c2"], pk["p"], recovered_x)["result"]["plaintext"]
            b_guess = 0 if recovered == (m0 % pk["p"]) else 1
        else:
            b_guess = random.randint(0, 1)
    else:
        b_guess = random.randint(0, 1)

    win = b_guess == b
    return {
        "result": {
            "challenge_bit": b,
            "guess": b_guess,
            "win": win,
            "advantage_estimate": 0.5 if force_tiny_group else 0.0,
            "ciphertext": c,
            "public_key": pk,
            "private_key": {"x": x},
        },
        "steps": [
            f"Challenge ciphertext encrypts m_b with b={b}",
            f"Adversary guess b'={b_guess}",
            f"Win={win}",
        ],
    }
