"""PA#13: Miller-Rabin primality testing and prime generation."""

import random
import time


def modexp(base: int, exponent: int, modulus: int) -> int:
    """Square-and-multiply modular exponentiation (no pow with modulus)."""
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    result = 1
    base = base % modulus
    e = exponent
    while e > 0:
        if e & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        e >>= 1
    return result


def miller_rabin(n: int, k: int = 40) -> dict:
    """Return PROBABLY PRIME or COMPOSITE using Miller-Rabin."""
    steps = [f"Input n={n}, rounds={k}"]

    if n < 2:
        return {"result": {"status": "COMPOSITE", "is_probable_prime": False}, "steps": [*steps, "n < 2"]}
    if n in (2, 3):
        return {"result": {"status": "PROBABLY PRIME", "is_probable_prime": True}, "steps": [*steps, "n in {2,3}"]}
    if n % 2 == 0:
        return {"result": {"status": "COMPOSITE", "is_probable_prime": False}, "steps": [*steps, "n is even"]}

    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    steps.append(f"n-1 = 2^{s} * {d}")

    for i in range(1, k + 1):
        a = random.randrange(2, n - 1)
        x = modexp(a, d, n)
        steps.append(f"Round {i}: a={a}, x=a^d mod n={x}")
        if x == 1 or x == n - 1:
            continue
        witness = True
        for r in range(1, s):
            x = modexp(x, 2, n)
            steps.append(f"  r={r}, x=x^2 mod n={x}")
            if x == n - 1:
                witness = False
                break
        if witness:
            steps.append("Found composite witness")
            return {"result": {"status": "COMPOSITE", "is_probable_prime": False}, "steps": steps}

    steps.append("No witness found")
    return {"result": {"status": "PROBABLY PRIME", "is_probable_prime": True}, "steps": steps}


def miller_rabin_test(n: int, rounds: int = 40) -> dict:
    """Backward-compatible wrapper."""
    out = miller_rabin(n, rounds)
    return {
        "result": {"is_probable_prime": out["result"]["is_probable_prime"], "status": out["result"]["status"]},
        "steps": out["steps"],
    }


def is_prime(n: int, rounds: int = 40) -> bool:
    return miller_rabin(n, rounds)["result"]["is_probable_prime"]


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Backward-compatible alias."""
    return is_prime(n, rounds)


def fermat_test(n: int, rounds: int = 5) -> dict:
    """Naive Fermat test for demonstration (can be fooled by Carmichael numbers)."""
    if n < 2:
        return {"result": {"passes": False}, "steps": ["n < 2"]}
    if n in (2, 3):
        return {"result": {"passes": True}, "steps": ["n in {2,3}"]}
    steps = []
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        val = modexp(a, n - 1, n)
        steps.append(f"a={a}, a^(n-1) mod n={val}")
        if val != 1:
            return {"result": {"passes": False}, "steps": steps}
    return {"result": {"passes": True}, "steps": steps}


def carmichael_demo() -> dict:
    """Show that 561 fools Fermat but not Miller-Rabin."""
    n = 561
    fermat = fermat_test(n, rounds=10)
    mr = miller_rabin(n, k=5)
    return {
        "result": {
            "n": n,
            "fermat_passes": fermat["result"]["passes"],
            "miller_rabin_prime": mr["result"]["is_probable_prime"],
        },
        "steps": [
            "Carmichael demo on n=561",
            *fermat["steps"],
            *mr["steps"],
        ],
    }


def gen_prime(bits: int, rounds: int = 40, sanity_rounds: int = 100) -> dict:
    """Generate a probable prime with sanity verification."""
    if bits < 3:
        raise ValueError("bits must be >= 3")

    attempts = 0
    steps = [f"Generating {bits}-bit prime with k={rounds}"]
    while True:
        attempts += 1
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1))
        candidate |= 1

        mr = miller_rabin(candidate, k=rounds)
        steps.append(f"Attempt {attempts}: candidate={candidate}, status={mr['result']['status']}")
        if not mr["result"]["is_probable_prime"]:
            continue

        sanity = miller_rabin(candidate, k=sanity_rounds)
        steps.append(f"Sanity check ({sanity_rounds} rounds): {sanity['result']['status']}")
        if sanity["result"]["is_probable_prime"]:
            return {
                "result": {"prime": candidate, "attempts": attempts},
                "steps": steps,
            }


def generate_prime(bits: int = 16, rounds: int = 40) -> dict:
    """Backward-compatible wrapper."""
    return gen_prime(bits, rounds=rounds, sanity_rounds=max(40, rounds))


def benchmark_prime_generation(bit_sizes: list[int] | None = None, trials: int = 3) -> dict:
    """Measure average attempts/time for requested prime sizes."""
    bit_sizes = bit_sizes or [512, 1024, 2048]
    data = []
    steps = []
    for bits in bit_sizes:
        total_attempts = 0
        total_seconds = 0.0
        for _ in range(trials):
            start = time.perf_counter()
            out = gen_prime(bits)
            total_seconds += time.perf_counter() - start
            total_attempts += out["result"]["attempts"]
        avg_attempts = total_attempts / trials
        avg_seconds = total_seconds / trials
        data.append({"bits": bits, "avg_attempts": avg_attempts, "avg_seconds": avg_seconds})
        steps.append(f"bits={bits}: avg_attempts={avg_attempts:.2f}, avg_seconds={avg_seconds:.4f}")

    return {"result": {"rows": data}, "steps": steps}
