"""PA#11: Diffie-Hellman key exchange, MITM demo, and CDH brute-force demo."""

import random
import time

from backend.core.pa13_miller_rabin.miller_rabin import gen_prime, is_prime, modexp


def _find_subgroup_generator(p: int, q: int) -> int:
    """Find g with order q in Z_p* where p=2q+1."""
    while True:
        h = random.randrange(2, p - 1)
        g = modexp(h, 2, p)
        if g != 1 and modexp(g, q, p) == 1:
            return g


def generate_safe_prime_group(bits: int = 24) -> dict:
    """Generate p=2q+1 with both p and q prime, and subgroup generator g of order q."""
    if bits < 8:
        raise ValueError("bits must be >= 8")

    q_bits = max(3, bits - 1)
    steps = [f"Generate safe-prime group target bits={bits}"]
    attempts = 0
    while True:
        attempts += 1
        q = gen_prime(q_bits, rounds=40)["result"]["prime"]
        p = 2 * q + 1
        if not is_prime(p, rounds=40):
            continue

        g = _find_subgroup_generator(p, q)
        steps.extend(
            [
                f"Found q={q}",
                f"Constructed p=2q+1={p}",
                f"Generator g={g} with g^q mod p = {modexp(g, q, p)}",
                f"Attempts={attempts}",
            ]
        )
        return {"result": {"p": p, "q": q, "g": g}, "steps": steps}


def dh_alice_step1(p: int, q: int, g: int, a: int | None = None) -> dict:
    if a is None:
        a = random.randrange(1, q)
    a_pub = modexp(g, a, p)
    return {
        "result": {"a": a, "A": a_pub},
        "steps": [f"Alice samples a in Z_q: a={a}", f"A=g^a mod p={a_pub}"],
    }


def dh_bob_step1(p: int, q: int, g: int, b: int | None = None) -> dict:
    if b is None:
        b = random.randrange(1, q)
    b_pub = modexp(g, b, p)
    return {
        "result": {"b": b, "B": b_pub},
        "steps": [f"Bob samples b in Z_q: b={b}", f"B=g^b mod p={b_pub}"],
    }


def dh_alice_step2(p: int, a: int, b_pub: int) -> dict:
    shared = modexp(b_pub, a, p)
    return {"result": {"K": shared}, "steps": [f"Alice computes K=B^a mod p={shared}"]}


def dh_bob_step2(p: int, b: int, a_pub: int) -> dict:
    shared = modexp(a_pub, b, p)
    return {"result": {"K": shared}, "steps": [f"Bob computes K=A^b mod p={shared}"]}


def diffie_hellman_exchange(p: int | None = None, g: int | None = None, a: int | None = None, b: int | None = None) -> dict:
    """Backward-compatible exchange function with generated or user-supplied params."""
    if p is None or g is None:
        group = generate_safe_prime_group(bits=24)["result"]
        p = group["p"]
        q = group["q"]
        g = group["g"]
    else:
        q = (p - 1) // 2 if (p - 1) % 2 == 0 else p - 1

    alice1 = dh_alice_step1(p, q, g, a)
    bob1 = dh_bob_step1(p, q, g, b)
    alice2 = dh_alice_step2(p, alice1["result"]["a"], bob1["result"]["B"])
    bob2 = dh_bob_step2(p, bob1["result"]["b"], alice1["result"]["A"])

    return {
        "result": {
            "p": p,
            "q": q,
            "g": g,
            "public_a": alice1["result"]["A"],
            "public_b": bob1["result"]["B"],
            "shared_secret": alice2["result"]["K"],
            "consistent": alice2["result"]["K"] == bob2["result"]["K"],
        },
        "steps": [
            f"Parameters: p={p}, q={q}, g={g}",
            *alice1["steps"],
            *bob1["steps"],
            *alice2["steps"],
            *bob2["steps"],
        ],
    }


def mitm_attack_demo(p: int, q: int, g: int, a: int | None = None, b: int | None = None, e: int | None = None) -> dict:
    """Active Eve substitutes both public values and shares separate secrets."""
    alice1 = dh_alice_step1(p, q, g, a)
    bob1 = dh_bob_step1(p, q, g, b)
    if e is None:
        e = random.randrange(1, q)

    eve_pub = modexp(g, e, p)
    k_alice = modexp(eve_pub, alice1["result"]["a"], p)
    k_bob = modexp(eve_pub, bob1["result"]["b"], p)
    k_eve_with_alice = modexp(alice1["result"]["A"], e, p)
    k_eve_with_bob = modexp(bob1["result"]["B"], e, p)

    return {
        "result": {
            "eve_public": eve_pub,
            "alice_shared_with_eve": k_alice,
            "bob_shared_with_eve": k_bob,
            "eve_with_alice": k_eve_with_alice,
            "eve_with_bob": k_eve_with_bob,
            "mitm_success": (k_alice == k_eve_with_alice) and (k_bob == k_eve_with_bob),
        },
        "steps": [
            "Eve intercepts A and B.",
            "Eve replaces both with E=g^e.",
            f"Alice computes K_A=(g^e)^a={k_alice}",
            f"Bob computes K_B=(g^e)^b={k_bob}",
            f"Eve computes A^e={k_eve_with_alice} and B^e={k_eve_with_bob}",
        ],
    }


def cdh_bruteforce_demo(p: int, g: int, a_pub: int, b_pub: int, max_exponent: int | None = None) -> dict:
    """Brute-force solve CDH for small groups by recovering a then g^(ab)."""
    bound = max_exponent if max_exponent is not None else p - 1
    start = time.perf_counter()

    recovered_a = None
    for guess in range(1, bound + 1):
        if modexp(g, guess, p) == a_pub:
            recovered_a = guess
            break

    if recovered_a is None:
        elapsed = time.perf_counter() - start
        return {
            "result": {"recovered": False, "elapsed_seconds": elapsed},
            "steps": ["Failed to recover exponent within bound"],
        }

    shared = modexp(b_pub, recovered_a, p)
    elapsed = time.perf_counter() - start
    return {
        "result": {
            "recovered": True,
            "recovered_a": recovered_a,
            "computed_g_ab": shared,
            "elapsed_seconds": elapsed,
        },
        "steps": [
            f"Recovered a={recovered_a} by brute force",
            f"Computed g^(ab)=B^a mod p={shared}",
            f"Elapsed seconds={elapsed:.6f}",
        ],
    }
