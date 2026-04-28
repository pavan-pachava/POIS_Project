from backend.core.pa5_mac.cbc_mac import cbc_mac, verify_cbc_mac
from backend.core.pa5_mac.prf_mac import prf_mac, verify_prf_mac


def test_prf_mac_verify_true_and_false():
    key = "1a2b3c4d"
    msg = "integrity-check"
    tag = prf_mac(key, msg)["tag"]
    verified = verify_prf_mac(key, msg, tag)
    assert verified["valid"] is True
    assert len(verified["steps"]) > 0
    assert verify_prf_mac(key, msg + "x", tag)["valid"] is False


def test_cbc_mac_deterministic_and_verify():
    key = "0f0f0f0f"
    msg = "hello world"
    first_result = cbc_mac(key, msg)
    first = first_result["tag"]
    second = cbc_mac(key, msg)["tag"]
    assert first == second
    assert first_result["block_count"] > 0
    verified = verify_cbc_mac(key, msg, first)
    assert verified["valid"] is True
    assert len(verified["steps"]) > 0
    assert verify_cbc_mac(key, msg, "00000000")["valid"] is False
