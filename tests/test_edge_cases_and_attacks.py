import logging
import random

from backend.core.pa10_hmac.hmac import toy_hmac
from backend.core.pa3_cpa_enc.attacks import simulate_cpa_attack, simulate_malleability_attack, simulate_nonce_reuse_attack
from backend.core.pa3_cpa_enc.dec import cpa_decrypt
from backend.core.pa3_cpa_enc.enc import cpa_encrypt
from backend.core.pa4_modes.cbc import cbc_decrypt, cbc_encrypt
from backend.core.pa4_modes.ctr import ctr_crypt
from backend.core.pa5_mac.prf_mac import prf_mac, verify_prf_mac
from backend.core.pa7_md.merkle_damgard import toy_hash
from backend.core.pa9_birthday.attack import birthday_collision_attack


def test_empty_input_edge_cases():
    key = "0a0b"

    enc = cpa_encrypt(key, "")
    dec = cpa_decrypt(key, enc["r"], enc["ciphertext"])
    assert enc["ciphertext"] == ""
    assert dec["plaintext"] == ""

    cbc = cbc_encrypt(key, b"", "00000001")
    cbc_dec = cbc_decrypt(key, cbc["result"]["ciphertext"], "00000001")
    assert cbc_dec["result"]["plaintext"] == ""

    ctr = ctr_crypt(key, b"", "00000001")
    assert ctr["result"]["output_hex"] == ""

    tag = prf_mac(key, "")["tag"]
    assert verify_prf_mac(key, "", tag)["valid"] is True

    assert len(toy_hash("")["digest"]) == 8
    assert len(toy_hmac(key, "")["result"]["tag"]) == 8


def test_large_input_edge_cases():
    key = "1a2b3c4d"
    large_message = "A" * 12000
    large_bytes = large_message.encode("utf-8")

    enc = cpa_encrypt(key, large_message)
    dec = cpa_decrypt(key, enc["r"], enc["ciphertext"])
    assert dec["plaintext"] == large_message

    ctr = ctr_crypt(key, large_bytes, "00000001")
    assert len(bytes.fromhex(ctr["result"]["output_hex"])) == len(large_bytes)

    assert prf_mac(key, large_message)["tag"]
    assert toy_hash(large_message)["digest"] == toy_hash(large_message)["digest"]


def test_cpa_attack_simulation_is_logged(caplog):
    with caplog.at_level(logging.INFO):
        simulation = simulate_cpa_attack("1a2b3c4d", "left-message", "right-message", challenge_bit=1, reused_nonce=11)

    assert simulation["result"]["success"] is True
    assert "CPA attack simulation" in caplog.text


def test_nonce_reuse_attack_simulation_is_logged(caplog):
    with caplog.at_level(logging.INFO):
        simulation = simulate_nonce_reuse_attack(
            "1a2b3c4d",
            known_plaintext="known-prefix-plaintext",
            target_plaintext="target-prefix-secret",
            reused_nonce=13,
        )

    assert simulation["result"]["success"] is True
    assert simulation["result"]["recovered_target_prefix"] == simulation["result"]["actual_target_prefix"]
    assert "Nonce reuse attack simulation" in caplog.text


def test_malleability_attack_changes_plaintext():
    simulation = simulate_malleability_attack("1a2b3c4d", plaintext="pay=100", flip_mask_hex="01", reused_nonce=9)
    assert simulation["result"]["original_plaintext"] != simulation["result"]["modified_plaintext"]
    assert simulation["result"]["plaintext_difference_hex"]


def test_birthday_attack_logs_results(caplog):
    with caplog.at_level(logging.INFO):
        result = birthday_collision_attack(truncate_bits=8, max_trials=4000)

    assert "found" in result["result"]
    assert "Birthday attack" in caplog.text


def test_birthday_attack_uses_exact_bit_prefix_for_supported_sizes():
    for bits in (8, 10, 12, 14, 16):
        random.seed(100 + bits)
        result = birthday_collision_attack(truncate_bits=bits, max_trials=12000)
        assert "attempts" in result["result"]
        if result["result"]["found"]:
            truncated = result["result"]["truncated_hash"]
            assert len(truncated) == bits
            assert set(truncated).issubset({"0", "1"})


def test_birthday_attack_rejects_unsupported_bit_lengths():
    try:
        birthday_collision_attack(truncate_bits=9, max_trials=100)
        assert False, "Expected ValueError for unsupported truncate_bits"
    except ValueError as error:
        message = str(error)
        assert message == "truncate_bits must be one of {8, 10, 12, 14, 16}"
