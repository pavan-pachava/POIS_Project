from backend.core.pa10_hmac.hmac import toy_hmac, verify_toy_hmac
from backend.core.pa11_dh.diffie_hellman import diffie_hellman_exchange
from backend.core.pa16_elgamal.elgamal import elgamal_decrypt, elgamal_encrypt, elgamal_keygen
from backend.core.pa13_miller_rabin.miller_rabin import miller_rabin_test
from backend.core.pa12_rsa.rsa import rsa_decrypt, rsa_encrypt, rsa_keygen
from backend.core.pa14_crt_attack.crt import crt_combine
from backend.core.pa15_signatures.signatures import elgamal_sign, elgamal_verify, rsa_sign, rsa_verify
from backend.core.pa18_ot.ot import simplified_ot_send_receive
from backend.core.pa19_secure_and.secure_and import secure_and_gate
from backend.core.pa20_mpc.mpc import two_party_compute_and
from backend.core.pa1_owf_prg.owf import simple_owf
from backend.core.pa1_owf_prg.prg import simple_prg
from backend.core.pa2_prf.ggm_prf import simple_prf
from backend.core.pa3_cpa_enc.dec import cpa_decrypt
from backend.core.pa3_cpa_enc.enc import cpa_encrypt
from backend.core.pa4_modes.cbc import cbc_decrypt, cbc_encrypt
from backend.core.pa4_modes.ctr import ctr_crypt
from backend.core.pa4_modes.ofb import ofb_crypt
from backend.core.pa5_mac.cbc_mac import cbc_mac, verify_cbc_mac
from backend.core.pa5_mac.prf_mac import prf_mac, verify_prf_mac
from backend.core.pa6_cca.cca_enc import cca_decrypt_then_verify, cca_encrypt_then_mac
from backend.core.pa7_md.merkle_damgard import toy_hash
from backend.core.pa8_dlp_hash.dlp_hash import dlp_hash
from backend.core.pa9_birthday.attack import birthday_collision_attack


def test_pa1_owf_and_prg_units():
    owf = simple_owf(7)
    assert isinstance(owf["output"], int)
    assert len(owf["steps"]) > 0

    prg = simple_prg("0a", output_bits=64)
    assert len(prg["output_bits"]) == 64
    assert len(prg["steps"]) > 0


def test_pa2_prf_unit():
    prf = simple_prf("0a0b", "1011")
    assert len(prf["output"]) == 8
    assert prf["query"] == "1011"


def test_pa3_cpa_encryption_unit():
    encrypted = cpa_encrypt("0a0b", "hello pa3")
    decrypted = cpa_decrypt("0a0b", encrypted["r"], encrypted["ciphertext"])
    assert decrypted["plaintext"] == "hello pa3"


def test_pa4_modes_units():
    key = "0a0b"
    iv_nonce = "00000001"
    message = b"hello pa4"

    cbc = cbc_encrypt(key, message, iv_nonce)
    cbc_plain = cbc_decrypt(key, cbc["result"]["ciphertext"], iv_nonce)
    assert bytes.fromhex(cbc_plain["result"]["plaintext_hex"]) == message

    ctr = ctr_crypt(key, message, iv_nonce)
    assert len(bytes.fromhex(ctr["result"]["output_hex"])) == len(message)

    ofb = ofb_crypt(key, message, iv_nonce)
    assert len(bytes.fromhex(ofb["result"]["output_hex"])) == len(message)


def test_pa5_mac_units():
    key = "0a0b"
    msg = "hello pa5"

    prf_tag = prf_mac(key, msg)["tag"]
    assert verify_prf_mac(key, msg, prf_tag)["valid"] is True

    cbc_tag = cbc_mac(key, msg)["tag"]
    assert verify_cbc_mac(key, msg, cbc_tag)["valid"] is True


def test_pa6_cca_unit():
    out = cca_encrypt_then_mac("0a0b", "0a0b", "hello pa6")
    dec = cca_decrypt_then_verify("0a0b", "0a0b", out["result"]["r"], out["result"]["ciphertext"], out["result"]["tag"])
    assert dec["result"]["accepted"] is True
    assert dec["result"]["plaintext"] == "hello pa6"


def test_pa7_pa8_pa9_pa10_units():
    assert len(toy_hash("hello pa7")["digest"]) == 8
    assert "digest" in dlp_hash("hello pa8")["result"]

    birthday = birthday_collision_attack(truncate_bits=8, max_trials=3000)
    assert "found" in birthday["result"]

    hmac = toy_hmac("0a0b", "hello pa10")
    assert verify_toy_hmac("0a0b", "hello pa10", hmac["result"]["tag"])["result"]["valid"] is True


def test_pa11_to_pa17_units():
    dh = diffie_hellman_exchange()
    assert dh["result"]["consistent"] is True

    rsa_keys = rsa_keygen(bits=32)["result"]
    pub = rsa_keys["public_key"]
    priv = rsa_keys["private_key"]
    ct = rsa_encrypt(42, pub["n"], pub["e"])["result"]["ciphertext"]
    pt = rsa_decrypt(ct, priv["n"], priv["d"], priv["p"], priv["q"])["result"]["plaintext"]
    assert pt == 42

    sig = rsa_sign("hello", pub["n"], priv["d"])["result"]["signature"]
    assert rsa_verify("hello", sig, pub["n"], pub["e"])["result"]["valid"] is True

    assert miller_rabin_test(97)["result"]["is_probable_prime"] is True
    crt = crt_combine(2, 3, 3, 5)["result"]["x"]
    assert crt % 3 == 2 and crt % 5 == 3

    eg = elgamal_keygen(bits=16)["result"]
    eg_pub = eg["public_key"]
    eg_priv = eg["private_key"]
    eg_ct = elgamal_encrypt(9, eg_pub["p"], eg_pub["g"], eg_pub["y"])["result"]["ciphertext"]
    assert elgamal_decrypt(eg_ct["c1"], eg_ct["c2"], eg_pub["p"], eg_priv["x"])["result"]["plaintext"] == 9

    eg_sig = elgamal_sign("hello", eg_pub["p"], eg_pub["g"], eg_priv["x"])["result"]["signature"]
    assert elgamal_verify("hello", eg_sig["r"], eg_sig["s"], eg_pub["p"], eg_pub["g"], eg_pub["y"])["result"]["valid"] is True


def test_pa18_to_pa20_units():
    assert simplified_ot_send_receive(10, 20, 1)["result"]["received_message"] == 20
    assert secure_and_gate(1, 1)["result"]["and"] == 1
    assert two_party_compute_and(1, 0)["result"]["and"] == 0
