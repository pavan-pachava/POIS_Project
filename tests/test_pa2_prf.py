"""PA#2: GGM PRF (simple_prf) and backward PRG-from-PRF (prg_from_prf).

Run from repo root:
    python -m pytest tests/test_pa2_prf.py -v
"""

from __future__ import annotations

import pytest

from backend.core.pa1_owf_prg.prg import simple_prg
from backend.core.pa2_prf.ggm_prf import (
    CHILD_BITS,
    EXPANSION_BITS,
    prg_from_prf,
    simple_prf,
)
from backend.core.utils.bit_utils import hex_to_int, int_to_hex


def _bits_to_hex(bits: str, *, min_bytes: int = 4) -> str:
    return int_to_hex(int(bits or "0", 2), min_bytes=min_bytes)


def _reference_ggm_output(key_hex: str, query_bits: str) -> dict[str, str]:
    """Independent GGM walk (must match slide algorithm + ggm_prf.simple_prf)."""
    clean = "".join(ch for ch in query_bits if ch in {"0", "1"})
    if not clean:
        clean = "0"
    state_hex = int_to_hex(hex_to_int(key_hex), min_bytes=4)
    for bit in clean:
        prg_out = simple_prg(state_hex, output_bits=EXPANSION_BITS)
        expanded = prg_out["output_bits"]
        left_bits = expanded[:CHILD_BITS]
        right_bits = expanded[CHILD_BITS:]
        left_hex = _bits_to_hex(left_bits)
        right_hex = _bits_to_hex(right_bits)
        state_hex = left_hex if bit == "0" else right_hex
    return {"output": int_to_hex(hex_to_int(state_hex), min_bytes=4), "query": clean}


@pytest.mark.parametrize(
    "key,query",
    [
        ("0f0f", "1011"),
        ("0a0b", "1011"),
        ("00", "0"),
        ("deadbeef", "010101"),
        ("cafe", "1100"),
        ("01", "1010101"),
    ],
)
def test_simple_prf_matches_independent_ggm_reference(key: str, query: str) -> None:
    got = simple_prf(key, query)
    ref = _reference_ggm_output(key, query)
    assert got["output"] == ref["output"]
    assert got["query"] == ref["query"]


def test_simple_prf_deterministic() -> None:
    a = simple_prf("a1b2", "101")
    b = simple_prf("a1b2", "101")
    assert a["output"] == b["output"]
    assert a["steps"] == b["steps"]


def test_query_strips_non_bits_and_defaults_empty_to_zero() -> None:
    assert simple_prf("ab", " 1\t0\n1 ")["query"] == "101"
    assert simple_prf("ab", "")["query"] == "0"
    assert simple_prf("ab", "xyz")["query"] == "0"


def test_step_trace_shape() -> None:
    out = simple_prf("feed", "10")
    steps = out["steps"]
    assert any("GGM PRF pipeline" in s for s in steps)
    assert any("Initial state s0" in s for s in steps)
    assert sum(1 for s in steps if "Bit 1=" in s) == 1
    assert sum(1 for s in steps if "Bit 2=" in s) == 1
    for line in steps:
        if "Bit " in line and "G(s" in line:
            assert "L=" in line and "R=" in line and "choose s" in line
    assert any("PRF output hex" in s for s in steps)
    assert len(steps) == len(out["query"]) + 3


def test_prg_expansion_bit_length() -> None:
    assert EXPANSION_BITS == CHILD_BITS * 2
    prg = simple_prg("abcd", output_bits=EXPANSION_BITS)
    assert len(prg["output_bits"]) == EXPANSION_BITS


def test_branch_selection_with_stub_prg(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force a known L/R split so we can prove bit 0 takes left and bit 1 takes right."""

    def stub_prg(seed_hex: str, output_bits: int = EXPANSION_BITS, **_: object) -> dict:
        assert output_bits == EXPANSION_BITS
        left = "0" * CHILD_BITS
        right = "1" * CHILD_BITS
        bits = left + right
        val = int(bits, 2)
        return {
            "seed": seed_hex,
            "output_bits": bits,
            "output_hex": int_to_hex(val, min_bytes=max(1, (output_bits + 7) // 8)),
            "steps": [f"stub PRG for seed={seed_hex}"],
        }

    monkeypatch.setattr("backend.core.pa2_prf.ggm_prf.simple_prg", stub_prg)

    key = "deadbeef"  # valid hex for key normalization
    left_hex = _bits_to_hex("0" * CHILD_BITS)
    right_hex = _bits_to_hex("1" * CHILD_BITS)

    z = simple_prf(key, "0")
    assert z["output"] == left_hex

    o = simple_prf(key, "1")
    assert o["output"] == right_hex

    two = simple_prf(key, "01")
    assert two["output"] == right_hex


def test_prg_from_prf_concatenates_fs_zero_and_fs_one() -> None:
    seed = "c0de"
    n = 12
    out = prg_from_prf(seed, block_bits=n)
    left = simple_prf(seed, "0" * n)
    right = simple_prf(seed, "1" * n)
    assert out["result"]["output_hex"] == left["output"] + right["output"]
    assert out["result"]["left_query"] == "0" * n
    assert out["result"]["right_query"] == "1" * n
    assert "Backward direction (PA#2b)" in " ".join(out["steps"])


def test_prg_from_prf_default_block_bits() -> None:
    out = prg_from_prf("beef")
    assert len(out["result"]["left_query"]) == 16
    assert len(out["result"]["right_query"]) == 16


def test_different_queries_usually_change_output() -> None:
    key = "babe"
    o0 = simple_prf(key, "0")["output"]
    o1 = simple_prf(key, "1")["output"]
    assert o0 != o1


def test_output_hex_width() -> None:
    out = simple_prf("0a0b", "1011")
    assert len(out["output"]) == 8
