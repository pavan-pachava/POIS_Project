from backend.core.pa1_owf_prg.prg import simple_prg
from backend.core.pa4_modes.cbc import cbc_decrypt, cbc_encrypt
from backend.core.pa5_mac.prf_mac import prf_mac, verify_prf_mac
from backend.core.pa6_cca.cca_enc import cca_decrypt_then_verify, cca_encrypt_then_mac
from backend.core.pa7_md.merkle_damgard import toy_hash
from backend.core.pa8_dlp_hash.dlp_hash import dlp_hash


def test_prg_basic_randomness_signal_across_seeds():
    out_a = simple_prg("0a", output_bits=32)["output_bits"]
    out_b = simple_prg("0b", output_bits=32)["output_bits"]
    assert out_a != out_b


def test_cbc_mode_encrypt_decrypt_roundtrip():
    key = "1a2b3c4d"
    plain = b"hello modes"
    enc = cbc_encrypt(key, plain, "00000001")
    dec = cbc_decrypt(key, enc["result"]["ciphertext"], "00000001")
    assert bytes.fromhex(dec["result"]["plaintext_hex"]) == plain


def test_cca_encrypt_then_mac_verification():
    key = "1a2b3c4d"
    enc = cca_encrypt_then_mac(key, key, "hello")
    dec = cca_decrypt_then_verify(
        key,
        key,
        enc["result"]["r"],
        enc["result"]["ciphertext"],
        enc["result"]["tag"],
    )
    assert dec["result"]["accepted"] is True
    assert dec["result"]["plaintext"] == "hello"


def test_mac_verification_still_works():
    tag = prf_mac("1a2b3c4d", "auth")["tag"]
    assert verify_prf_mac("1a2b3c4d", "auth", tag)["valid"] is True


def test_hash_consistency_for_md_and_dlp_hash():
    md1 = toy_hash("consistency")["digest"]
    md2 = toy_hash("consistency")["digest"]
    assert md1 == md2

    dlp1 = dlp_hash("consistency")["result"]["digest"]
    dlp2 = dlp_hash("consistency")["result"]["digest"]
    assert dlp1 == dlp2
