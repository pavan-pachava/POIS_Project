from backend.core.pa2_prf.ggm_prf import simple_prf


def test_prf_deterministic_for_same_key_query():
    a = simple_prf("0f0f", "1011")
    b = simple_prf("0f0f", "1011")
    assert a["output"] == b["output"]
