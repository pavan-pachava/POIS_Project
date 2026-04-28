"""PA#1: Toy PRG from iterative OWF + least-significant-bit extraction."""

from backend.core.pa1_owf_prg.owf import simple_owf
from backend.core.utils.bit_utils import hex_to_int, int_to_hex


def simple_prg(seed_hex: str, output_bits: int = 32, g: int = 5, p: int = 2147483647) -> dict:
    """Generate pseudorandom bits by iterating the OWF and extracting 1 bit/round."""
    state = hex_to_int(seed_hex) % p
    bits = []
    steps = [f"Initial state from seed = {state}"]

    for i in range(output_bits):
        owf_result = simple_owf(state, g=g, p=p)
        state = owf_result["output"]
        bit = state & 1
        bits.append(str(bit))
        steps.append(f"Round {i + 1}: state={state}, extracted_bit={bit}")

    bit_string = "".join(bits)
    output_int = int(bit_string, 2) if bit_string else 0
    output_hex = int_to_hex(output_int, min_bytes=max(1, (output_bits + 7) // 8))

    steps.append(f"Output bits = {bit_string}")
    steps.append(f"Output hex = {output_hex}")

    return {"seed": seed_hex, "output_bits": bit_string, "output_hex": output_hex, "steps": steps}


def prg_as_owf(seed_hex: str, output_bits: int = 64, g: int = 5, p: int = 2147483647) -> dict:
    """PA#1 backward direction witness: define one-way f(s)=G(s)."""
    prg = simple_prg(seed_hex, output_bits=output_bits, g=g, p=p)
    return {
        "result": {
            "owf_input_seed": seed_hex,
            "owf_output": prg["output_hex"],
        },
        "steps": [
            "Backward direction (PA#1b): set f(s)=G(s).",
            *prg["steps"],
            "Given y=G(s), recovering s is inversion of the PRG output map (treated one-way).",
        ],
    }
