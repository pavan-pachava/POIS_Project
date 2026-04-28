"""PA#3: CPA encryption (cpa_encrypt / cpa_decrypt) and attack simulations.

Run from repo root:
    python -m pytest tests/test_pa3_cpa.py -v
"""

from __future__ import annotations

import secrets

import pytest

from backend.core.pa3_cpa_enc.attacks import (
    _encrypt_with_fixed_nonce,
    simulate_cpa_attack,
)
from backend.core.pa3_cpa_enc.dec import cpa_decrypt
from backend.core.pa3_cpa_enc.enc import cpa_encrypt


def test_cpa_round_trip_ascii() -> None:
    key = "1a2b3c4d"
    message = "hello pa3"
    enc = cpa_encrypt(key, message)
    dec = cpa_decrypt(key, enc["r"], enc["ciphertext"])
    assert dec["plaintext"] == message


def test_cpa_round_trip_multiblock_long_message() -> None:
    """Multi-block path: keystream extends via counter inside _keystream_from_prf."""
    key = "beefcafe"
    message = "A" * 120
    enc = cpa_encrypt(key, message)
    dec = cpa_decrypt(key, enc["r"], enc["ciphertext"])
    assert dec["plaintext"] == message


def test_cpa_round_trip_empty_message() -> None:
    key = "00ff"
    enc = cpa_encrypt(key, "")
    dec = cpa_decrypt(key, enc["r"], enc["ciphertext"])
    assert dec["plaintext"] == ""


def test_cpa_round_trip_unicode() -> None:
    key = "abc12345"
    message = "日本語 τεστ emoji 🔐"
    enc = cpa_encrypt(key, message)
    dec = cpa_decrypt(key, enc["r"], enc["ciphertext"])
    assert dec["plaintext"] == message


def test_encrypt_returns_r_ciphertext_and_steps() -> None:
    enc = cpa_encrypt("deadbeef", "x")
    assert "r" in enc and "ciphertext" in enc and "steps" in enc
    assert isinstance(enc["r"], str)
    assert isinstance(enc["ciphertext"], str)
    assert len(enc["steps"]) >= 1


def test_fresh_nonce_makes_two_encryptions_differ() -> None:
    """Same plaintext must not imply same ciphertext when r is fresh each time."""
    key = "c0dec0de"
    plaintext = "identical"
    out = {cpa_encrypt(key, plaintext)["ciphertext"] for _ in range(25)}
    assert len(out) == 25


def test_ciphertext_byte_length_matches_plaintext() -> None:
    key = "ab12cd34"
    for msg in ("hi", "x" * 200):
        enc = cpa_encrypt(key, msg)
        # hex length = 2 * byte length
        assert len(enc["ciphertext"]) == 2 * len(msg.encode("utf-8"))


def test_ind_cpa_dummy_adversary_random_guess_near_half() -> None:
    """IND-CPA: a random-guess adversary should win ~50% (challenge is independent of guess).

    The course spec mentions 50 oracle queries; we use fewer here so pytest stays quick.
    """
    key = "baddcaf3"
    m0 = "0123456789"
    m1 = "abcdefghij"
    assert len(m0) == len(m1)

    # Keep counts modest: each call runs PRF-derived keystream work.
    oracle_queries = 4
    trials = 50
    wins = 0
    for _ in range(trials):
        for _ in range(oracle_queries):
            cpa_encrypt(key, f"o-{secrets.token_hex(2)}")

        b = secrets.randbelow(2)
        cpa_encrypt(key, m0 if b == 0 else m1)
        guess = secrets.randbelow(2)
        if guess == b:
            wins += 1

    rate = wins / trials
    assert 0.28 < rate < 0.72, f"expected ~0.5, got {rate}"


def test_broken_fixed_nonce_same_plaintext_same_ciphertext() -> None:
    """Broken scheme: reuse r => encrypting the same message twice yields same c."""
    key = "f00dbabe"
    nonce = 12345
    c1, _ = _encrypt_with_fixed_nonce(key, "same", nonce)
    c2, _ = _encrypt_with_fixed_nonce(key, "same", nonce)
    assert c1 == c2


def test_broken_fixed_nonce_distinguishing_two_messages() -> None:
    """With fixed nonce, encryptions of m0 and m1 are distinct labels adversary can compare."""
    key = "abcdbcbc"
    m0, m1 = "hello", "world"
    c0, _ = _encrypt_with_fixed_nonce(key, m0, 99)
    c1, _ = _encrypt_with_fixed_nonce(key, m1, 99)
    assert c0 != c1

    sim = simulate_cpa_attack(key, m0, m1, challenge_bit=0, reused_nonce=99, trials=1)
    assert sim["result"]["adversary_guess"] == 0
    assert sim["result"]["success"] is True

    sim2 = simulate_cpa_attack(key, m0, m1, challenge_bit=1, reused_nonce=99, trials=1)
    assert sim2["result"]["adversary_guess"] == 1
    assert sim2["result"]["success"] is True


def test_wrong_key_fails_to_recover_plaintext() -> None:
    enc = cpa_encrypt("11111111", "secret")
    dec = cpa_decrypt("22222222", enc["r"], enc["ciphertext"])
    assert dec["plaintext"] != "secret"
