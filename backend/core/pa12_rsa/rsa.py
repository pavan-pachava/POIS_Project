"""PA#12: Textbook RSA + PKCS#1 v1.5 + attack demos."""

import math
import secrets

from backend.core.pa13_miller_rabin.miller_rabin import gen_prime, modexp
from backend.core.pa14_crt_attack.crt import mod_inverse, rsa_dec_crt

DEFAULT_E = 65537


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def _int_to_bytes(value: int, length: int | None = None) -> bytes:
    if value < 0:
        raise ValueError("value must be non-negative")
    if value == 0:
        out = b"\x00"
    else:
        size = (value.bit_length() + 7) // 8
        out = value.to_bytes(size, "big")
    if length is not None:
        if len(out) > length:
            raise ValueError("value too large for requested byte length")
        return out.rjust(length, b"\x00")
    return out


def _bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def rsa_keygen(bits: int = 512, e: int = DEFAULT_E) -> dict:
    """Generate RSA keys and CRT parameters (p,q,dp,dq,q_inv)."""
    if bits < 16:
        raise ValueError("bits must be >= 16")

    half = bits // 2
    p = gen_prime(half)["result"]["prime"]
    q = gen_prime(half)["result"]["prime"]
    while q == p:
        q = gen_prime(half)["result"]["prime"]

    n = p * q
    phi = (p - 1) * (q - 1)
    chosen_e = e
    if _gcd(chosen_e, phi) != 1:
        chosen_e = 3
        while chosen_e < phi and _gcd(chosen_e, phi) != 1:
            chosen_e += 2

    d = mod_inverse(chosen_e, phi)
    dp = d % (p - 1)
    dq = d % (q - 1)
    q_inv = mod_inverse(q, p)

    return {
        "result": {
            "public_key": {"n": n, "e": chosen_e},
            "private_key": {"n": n, "d": d, "p": p, "q": q, "dp": dp, "dq": dq, "q_inv": q_inv},
        },
        "steps": [
            f"Generate p={p}, q={q}",
            f"n=p*q={n}",
            f"phi(n)={(p - 1) * (q - 1)}",
            f"e={chosen_e}, d=e^-1 mod phi={d}",
            f"CRT params dp={dp}, dq={dq}, q_inv={q_inv}",
        ],
    }


def rsa_encrypt(message_int: int, n: int, e: int) -> dict:
    if message_int < 0 or message_int >= n:
        raise ValueError("message_int must satisfy 0 <= m < n")
    c = modexp(message_int, e, n)
    return {"result": {"ciphertext": c}, "steps": [f"c = m^e mod n = {c}"]}


def rsa_decrypt(ciphertext_int: int, n: int, d: int, p: int | None = None, q: int | None = None) -> dict:
    if p is not None and q is not None:
        dp = d % (p - 1)
        dq = d % (q - 1)
        q_inv = mod_inverse(q, p)
        sk = {"p": p, "q": q, "dp": dp, "dq": dq, "q_inv": q_inv}
        out = rsa_dec_crt(sk, ciphertext_int, modexp)
        return {"result": {"plaintext": out["result"]["plaintext"]}, "steps": out["steps"]}

    m = modexp(ciphertext_int, d, n)
    return {"result": {"plaintext": m}, "steps": [f"m = c^d mod n = {m}"]}


def _pkcs15_pad_for_encryption(message: bytes, modulus_bytes: int) -> tuple[bytes, bytes]:
    if len(message) > modulus_bytes - 11:
        raise ValueError("message too long for PKCS#1 v1.5")

    ps_len = modulus_bytes - len(message) - 3
    if ps_len < 8:
        raise ValueError("padding string too short")

    ps = bytearray()
    while len(ps) < ps_len:
        b = secrets.token_bytes(1)
        if b != b"\x00":
            ps.extend(b)

    em = b"\x00\x02" + bytes(ps) + b"\x00" + message
    return em, bytes(ps)


def _pkcs15_unpad_from_encryption(encoded: bytes) -> bytes | None:
    if len(encoded) < 11:
        return None
    if not encoded.startswith(b"\x00\x02"):
        return None

    idx = encoded.find(b"\x00", 2)
    if idx == -1:
        return None
    if idx < 10:
        return None
    return encoded[idx + 1 :]


def pkcs15_encrypt(message: bytes, n: int, e: int) -> dict:
    k = max(1, math.ceil(n.bit_length() / 8))
    em, ps = _pkcs15_pad_for_encryption(message, k)
    c = modexp(_bytes_to_int(em), e, n)
    return {
        "result": {
            "ciphertext": c,
            "padding_bytes_hex": ps.hex(),
            "encoded_message_hex": em.hex(),
        },
        "steps": [
            f"k={k} bytes modulus",
            "Build EM = 00||02||PS||00||m",
            f"PS length={len(ps)} bytes",
            f"Ciphertext c={c}",
        ],
    }


def pkcs15_decrypt(ciphertext: int, n: int, d: int) -> dict:
    k = max(1, math.ceil(n.bit_length() / 8))
    em_int = modexp(ciphertext, d, n)
    em = _int_to_bytes(em_int, k)
    msg = _pkcs15_unpad_from_encryption(em)
    if msg is None:
        return {"result": {"plaintext": None, "valid_padding": False}, "steps": ["Malformed PKCS#1 v1.5 padding"]}
    return {
        "result": {"plaintext": msg, "valid_padding": True},
        "steps": ["Valid PKCS#1 v1.5 structure", f"Recovered message bytes len={len(msg)}"],
    }


def textbook_determinism_demo(message_int: int, n: int, e: int) -> dict:
    c1 = modexp(message_int, e, n)
    c2 = modexp(message_int, e, n)
    return {
        "result": {"c1": c1, "c2": c2, "identical": c1 == c2},
        "steps": ["Textbook RSA deterministic encryption", f"c1={c1}", f"c2={c2}"],
    }


def pkcs15_randomization_demo(message: bytes, n: int, e: int) -> dict:
    out1 = pkcs15_encrypt(message, n, e)
    out2 = pkcs15_encrypt(message, n, e)
    return {
        "result": {
            "c1": out1["result"]["ciphertext"],
            "c2": out2["result"]["ciphertext"],
            "identical": out1["result"]["ciphertext"] == out2["result"]["ciphertext"],
            "ps1": out1["result"]["padding_bytes_hex"],
            "ps2": out2["result"]["padding_bytes_hex"],
        },
        "steps": ["PKCS#1 v1.5 randomized padding demo", *out1["steps"], *out2["steps"]],
    }


def bleichenbacher_toy_oracle(ciphertext: int, n: int, d: int) -> bool:
    """Padding oracle: returns only validity bit for PKCS#1 v1.5 format."""
    return bool(pkcs15_decrypt(ciphertext, n, d)["result"]["valid_padding"])


def bleichenbacher_toy_demo(ciphertext: int, n: int, e: int, d: int, max_s: int = 1 << 16) -> dict:
    """Simplified adaptive search for a blinding multiplier producing valid padding."""
    steps = ["Start toy Bleichenbacher adaptive search"]
    queries = 0

    for s in range(2, max_s):
        blinded = (ciphertext * modexp(s, e, n)) % n
        queries += 1
        if bleichenbacher_toy_oracle(blinded, n, d):
            steps.append(f"Found valid padding at multiplier s={s} after {queries} oracle queries")
            return {
                "result": {
                    "queries": queries,
                    "found_multiplier": s,
                    "oracle_success": True,
                },
                "steps": steps,
            }

    steps.append("No valid multiplier found within bound")
    return {
        "result": {"queries": queries, "found_multiplier": None, "oracle_success": False},
        "steps": steps,
    }
