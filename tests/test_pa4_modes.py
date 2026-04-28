"""PA#4: CBC, OFB, and CTR modes (toy 4-byte block size).

Run from repo root:
    python -m pytest tests/test_pa4_modes.py -v
"""

from __future__ import annotations

import pytest

from backend.core.pa4_modes.cbc import BLOCK_BYTES as CBC_BLOCK
from backend.core.pa4_modes.cbc import cbc_decrypt, cbc_encrypt
from backend.core.pa4_modes.ctr import BLOCK_BYTES as CTR_BLOCK
from backend.core.pa4_modes.ctr import ctr_crypt
from backend.core.pa4_modes.ofb import BLOCK_BYTES as OFB_BLOCK
from backend.core.pa4_modes.ofb import ofb_crypt
from backend.core.utils.bit_utils import hex_to_bytes, xor_bytes


# 4-byte IV/nonce (hex = 8 hex chars) — required by toy implementations
IV = "00000001"
NONCE = "00000002"
KEY = "1a2b3c4d"


def _cbc_roundtrip(plaintext: bytes) -> None:
    enc = cbc_encrypt(KEY, plaintext, IV)
    dec = cbc_decrypt(KEY, enc["result"]["ciphertext"], IV)
    assert bytes.fromhex(dec["result"]["plaintext_hex"]) == plaintext


def _ctr_roundtrip(plaintext: bytes) -> None:
    enc = ctr_crypt(KEY, plaintext, NONCE)
    c = hex_to_bytes(enc["result"]["output_hex"])
    dec = ctr_crypt(KEY, c, NONCE)
    assert hex_to_bytes(dec["result"]["output_hex"]) == plaintext


def _ofb_roundtrip(plaintext: bytes) -> None:
    enc = ofb_crypt(KEY, plaintext, IV)
    c = hex_to_bytes(enc["result"]["output_hex"])
    dec = ofb_crypt(KEY, c, IV)
    assert hex_to_bytes(dec["result"]["output_hex"]) == plaintext


@pytest.mark.parametrize("mode_fn", [_cbc_roundtrip, _ctr_roundtrip, _ofb_roundtrip], ids=["CBC", "CTR", "OFB"])
def test_mode_roundtrip_shorter_than_one_block(mode_fn) -> None:
    """One byte: shorter than 4-byte toy block (PKCS7 / stream covers tail)."""
    mode_fn(b"X")


@pytest.mark.parametrize("mode_fn", [_cbc_roundtrip, _ctr_roundtrip, _ofb_roundtrip], ids=["CBC", "CTR", "OFB"])
def test_mode_roundtrip_exactly_one_block(mode_fn) -> None:
    """Exactly one 4-byte block."""
    mode_fn(b"ABCD")


@pytest.mark.parametrize("mode_fn", [_cbc_roundtrip, _ctr_roundtrip, _ofb_roundtrip], ids=["CBC", "CTR", "OFB"])
def test_mode_roundtrip_multiple_blocks(mode_fn) -> None:
    """Spans multiple toy blocks."""
    mode_fn(b"Hello, PA#4 modes!")


def test_cbc_steps_include_iv_and_blocks() -> None:
    enc = cbc_encrypt(KEY, b"test", IV)
    assert enc["result"]["mode"] == "CBC"
    assert enc["result"]["iv"] == IV.lower()
    assert "blocks" in enc["result"]
    assert len(enc["steps"]) >= 2


def test_ctr_parallel_block_metadata() -> None:
    """CTR exposes per-counter block view (parallel structure)."""
    data = b"abcdefghijklmnop"  # 16 bytes = 4 toy blocks
    out = ctr_crypt(KEY, data, NONCE)
    blocks = out["result"]["blocks"]
    assert len(blocks) == 4
    assert {b["counter"] for b in blocks} == {0, 1, 2, 3}


def test_ofb_encrypt_decrypt_same_primitive() -> None:
    """OFB: encryption and decryption are the same XOR keystream operation."""
    plain = b"ofb-symmetric"
    c = ofb_crypt(KEY, plain, IV)
    c_bytes = hex_to_bytes(c["result"]["output_hex"])
    p2 = ofb_crypt(KEY, c_bytes, IV)
    assert hex_to_bytes(p2["result"]["output_hex"]) == plain


def test_ofb_keystream_reuse_xor_leaks_plaintext_xor() -> None:
    """Same IV: c1 xor c2 == p1 xor p2 (OFB is stream cipher)."""
    p1 = b"same-iv-msg-a!!"
    p2 = b"same-iv-msg-b!!"
    assert len(p1) == len(p2)
    c1 = hex_to_bytes(ofb_crypt(KEY, p1, IV)["result"]["output_hex"])
    c2 = hex_to_bytes(ofb_crypt(KEY, p2, IV)["result"]["output_hex"])
    assert xor_bytes(c1, c2) == xor_bytes(p1, p2)


def test_cbc_same_iv_matching_first_plaintext_block_implies_matching_ciphertext_block() -> None:
    """CBC IV reuse: identical first block of plaintext => identical first ciphertext block."""
    m1 = b"HELL" + b"aaaa"
    m2 = b"HELL" + b"bbbb"
    assert m1[:CBC_BLOCK] == m2[:CBC_BLOCK]
    e1 = cbc_encrypt(KEY, m1, IV)
    e2 = cbc_encrypt(KEY, m2, IV)
    ct1 = hex_to_bytes(e1["result"]["ciphertext"])
    ct2 = hex_to_bytes(e2["result"]["ciphertext"])
    assert ct1[:CBC_BLOCK] == ct2[:CBC_BLOCK]
    assert ct1 != ct2


def test_cbc_different_iv_changes_ciphertext() -> None:
    plain = b"fixed-plaintext"
    c1 = cbc_encrypt(KEY, plain, "01020304")["result"]["ciphertext"]
    c2 = cbc_encrypt(KEY, plain, "05060708")["result"]["ciphertext"]
    assert c1 != c2


def test_cbc_wrong_iv_fails_roundtrip() -> None:
    enc = cbc_encrypt(KEY, b"secret", IV)
    dec = cbc_decrypt(KEY, enc["result"]["ciphertext"], "0a0b0c0d")
    assert bytes.fromhex(dec["result"]["plaintext_hex"]) != b"secret"


def test_cbc_decrypt_rejects_bad_padding() -> None:
    enc = cbc_encrypt(KEY, b"ok", IV)
    ct = bytearray(hex_to_bytes(enc["result"]["ciphertext"]))
    ct[-1] ^= 0xFF
    bad_hex = ct.hex()
    with pytest.raises(ValueError, match="PKCS|padding|Invalid"):
        cbc_decrypt(KEY, bad_hex, IV)


def test_block_sizes_documented() -> None:
    assert CBC_BLOCK == CTR_BLOCK == OFB_BLOCK == 4
