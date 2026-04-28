"""PA#14: CRT solver, RSA CRT decryption, and Hastad broadcast attack."""

import math
import time


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def mod_inverse(a: int, n: int) -> int:
    g, x, _ = egcd(a, n)
    if g != 1:
        raise ValueError("mod inverse does not exist")
    return x % n


def crt(residues: list[int], moduli: list[int]) -> dict:
    """General CRT reconstruction for pairwise-coprime moduli."""
    if len(residues) != len(moduli) or not residues:
        raise ValueError("residues and moduli must be same non-zero length")

    n_prod = 1
    for n in moduli:
        if n <= 0:
            raise ValueError("moduli must be positive")
        n_prod *= n

    x = 0
    steps = [f"N = product(moduli) = {n_prod}"]
    for a_i, n_i in zip(residues, moduli):
        m_i = n_prod // n_i
        inv_i = mod_inverse(m_i % n_i, n_i)
        term = a_i * m_i * inv_i
        x = (x + term) % n_prod
        steps.append(f"a={a_i}, n={n_i}, M_i={m_i}, inv={inv_i}, partial={x}")

    return {"result": {"x": x, "modulus": n_prod}, "steps": steps}


def crt_combine(a1: int, n1: int, a2: int, n2: int) -> dict:
    """Backward-compatible 2-moduli CRT helper."""
    out = crt([a1, a2], [n1, n2])
    return {"result": {"x": out["result"]["x"], "modulus": out["result"]["modulus"]}, "steps": out["steps"]}


def rsa_dec_crt(sk: dict, ciphertext: int, modexp_fn) -> dict:
    """Garner-based CRT decryption; sk needs p,q,dp,dq,q_inv."""
    p = int(sk["p"])
    q = int(sk["q"])
    dp = int(sk["dp"])
    dq = int(sk["dq"])
    q_inv = int(sk["q_inv"])

    mp = modexp_fn(ciphertext, dp, p)
    mq = modexp_fn(ciphertext, dq, q)
    h = (q_inv * (mp - mq)) % p
    m = mq + h * q

    return {
        "result": {"plaintext": m},
        "steps": [
            f"mp=c^dp mod p={mp}",
            f"mq=c^dq mod q={mq}",
            f"h=q_inv*(mp-mq) mod p={h}",
            f"m=mq+h*q={m}",
        ],
    }


def _integer_nth_root(value: int, n: int) -> int:
    if value < 0:
        raise ValueError("value must be non-negative")
    if value in (0, 1):
        return value

    x = int(round(value ** (1.0 / n)))
    x = max(1, x)
    while True:
        num = (n - 1) * x + value // (x ** (n - 1))
        nxt = num // n
        if nxt >= x:
            break
        x = nxt
    while (x + 1) ** n <= value:
        x += 1
    while x ** n > value:
        x -= 1
    return x


def hastad_attack(ciphertexts: list[int], moduli: list[int], e: int) -> dict:
    """Recover plaintext for textbook broadcast under small exponent e."""
    if len(ciphertexts) < e or len(moduli) < e:
        raise ValueError("Need at least e ciphertexts/moduli")

    c = ciphertexts[:e]
    n = moduli[:e]
    crt_out = crt(c, n)
    x = crt_out["result"]["x"]
    m = _integer_nth_root(x, e)

    return {
        "result": {
            "m_power_e": x,
            "recovered_message": m,
            "exact_root": (m**e == x),
        },
        "steps": [
            "Run CRT over ciphertext congruences.",
            *crt_out["steps"],
            f"Take integer {e}-th root of x: m={m}",
            f"Check m^e == x: {m**e == x}",
        ],
    }


def hastad_attack_boundary(moduli_bits: list[int], e: int = 3) -> dict:
    """Maximum message bytes where m^e < product(moduli) can hold approximately."""
    total_bits = sum(moduli_bits)
    max_m_bits = total_bits // e
    max_m_bytes = max_m_bits // 8
    return {
        "result": {
            "moduli_bits": moduli_bits,
            "total_bits": total_bits,
            "max_message_bits": max_m_bits,
            "max_message_bytes": max_m_bytes,
        },
        "steps": [
            f"Condition for attack success: m^{e} < N1*...*Ne",
            f"Approximate bound bits(m) < (sum bits(Ni))/e = {max_m_bits}",
            f"Max whole bytes: {max_m_bytes}",
        ],
    }


def rsa_crt_speed_benchmark(dec_standard, dec_crt, key_builder, bits_list: list[int] | None = None, trials: int = 100) -> dict:
    """Benchmark standard vs CRT decryption for provided key sizes."""
    bits_list = bits_list or [1024, 2048]
    rows = []
    steps = []

    for bits in bits_list:
        key = key_builder(bits)
        n = key["public_key"]["n"]
        d = key["private_key"]["d"]
        p = key["private_key"]["p"]
        q = key["private_key"]["q"]
        sk = {
            "p": p,
            "q": q,
            "dp": key["private_key"]["dp"],
            "dq": key["private_key"]["dq"],
            "q_inv": key["private_key"]["q_inv"],
        }

        ctexts = [42 + i for i in range(trials)]
        ctexts = [pow(m % n, key["public_key"]["e"], n) for m in ctexts]

        t0 = time.perf_counter()
        for c in ctexts:
            dec_standard(c, n, d, p, q)
        t_standard = time.perf_counter() - t0

        t1 = time.perf_counter()
        for c in ctexts:
            dec_crt(sk, c)
        t_crt = time.perf_counter() - t1

        speedup = (t_standard / t_crt) if t_crt > 0 else math.inf
        rows.append({"bits": bits, "standard_seconds": t_standard, "crt_seconds": t_crt, "speedup": speedup})
        steps.append(f"bits={bits}: standard={t_standard:.6f}s, crt={t_crt:.6f}s, speedup={speedup:.3f}x")

    return {"result": {"rows": rows}, "steps": steps}
