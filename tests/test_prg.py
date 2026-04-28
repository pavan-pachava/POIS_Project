from backend.core.pa1_owf_prg.prg import simple_prg


def test_prg_output_length_matches_bits():
    result = simple_prg("0a", output_bits=16)
    assert len(result["output_bits"]) == 16
    assert len(result["output_hex"]) == 4
