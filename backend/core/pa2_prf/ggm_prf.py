"""PA#2: Toy GGM PRF built by treating PA#1 PRG as a black-box expansion oracle."""

from backend.core.pa1_owf_prg.prg import simple_prg
from backend.core.utils.bit_utils import hex_to_int, int_to_hex


CHILD_BITS = 32
EXPANSION_BITS = CHILD_BITS * 2


def _bits_to_hex(bits: str, *, min_bytes: int = 4) -> str:
    """Convert a bit-string to hex with stable zero-padding for state transitions."""
    return int_to_hex(int(bits or "0", 2), min_bytes=min_bytes)


def simple_prf(key_hex: str, query_bits: str) -> dict:
    """Evaluate GGM PRF: repeatedly expand with PRG and select left/right by query bit."""
    clean_query = "".join(ch for ch in query_bits if ch in {"0", "1"})
    if not clean_query:
        clean_query = "0"

    # Normalize to a fixed-width state so every G(s) split yields L/R states of equal size.
    s_current_hex = int_to_hex(hex_to_int(key_hex), min_bytes=4)
    steps = [
        "GGM PRF pipeline: s0 = k, for each query bit xi compute G(si-1)=(L,R), then choose L for 0 or R for 1.",
        f"Initial state s0 (from key) = {s_current_hex}",
    ]

    for index, bit in enumerate(clean_query, start=1):
        # PRG is used as a black box: no custom local expansion logic is allowed here.
        prg_out = simple_prg(s_current_hex, output_bits=EXPANSION_BITS)
        expanded_bits = prg_out["output_bits"]
        left_bits = expanded_bits[:CHILD_BITS]
        right_bits = expanded_bits[CHILD_BITS:]
        left_hex = _bits_to_hex(left_bits)
        right_hex = _bits_to_hex(right_bits)
        chosen_hex = left_hex if bit == "0" else right_hex
        steps.append(
            f"Bit {index}='{bit}': G(s{index - 1}) from PRG({s_current_hex}) -> "
            f"L={left_hex}, R={right_hex}; choose s{index}={chosen_hex}"
        )
        s_current_hex = chosen_hex

    output_hex = int_to_hex(hex_to_int(s_current_hex), min_bytes=4)
    steps.append(f"PRF output hex = {output_hex}")

    return {
        "key": key_hex,
        "query": clean_query,
        "output": output_hex,
        "steps": steps,
    }


def prg_from_prf(seed_key_hex: str, block_bits: int = 16) -> dict:
    """PA#2 backward direction: G(s)=F_s(0^n)||F_s(1^n)."""
    n_zeros = "0" * block_bits
    n_ones = "1" * block_bits
    left = simple_prf(seed_key_hex, n_zeros)
    right = simple_prf(seed_key_hex, n_ones)
    out_hex = f"{left['output']}{right['output']}"
    return {
        "result": {
            "seed": seed_key_hex,
            "left_query": n_zeros,
            "right_query": n_ones,
            "output_hex": out_hex,
        },
        "steps": [
            "Backward direction (PA#2b): build PRG from PRF.",
            f"Evaluate F_s(0^n) with n={block_bits}",
            *left["steps"],
            f"Evaluate F_s(1^n) with n={block_bits}",
            *right["steps"],
            f"Concatenate outputs: G(s)=F_s(0^n)||F_s(1^n)={out_hex}",
        ],
    }
