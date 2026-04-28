from backend.core.builder import build_primitive
from backend.core.pa10_hmac.hmac import toy_hmac
from backend.core.pa11_dh.diffie_hellman import diffie_hellman_exchange
from backend.core.pa16_elgamal.elgamal import elgamal_decrypt, elgamal_encrypt, elgamal_keygen
from backend.core.pa13_miller_rabin.miller_rabin import miller_rabin_test
from backend.core.pa12_rsa.rsa import rsa_decrypt, rsa_encrypt, rsa_keygen
from backend.core.pa14_crt_attack.crt import crt_combine
from backend.core.pa15_signatures.signatures import rsa_sign, rsa_verify
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
from backend.core.reduce_executor import execute_reduction


def _has_steps(value: dict):
    assert "steps" in value
    assert isinstance(value["steps"], list)
    assert len(value["steps"]) > 0


def test_pa1_to_pa10_smoke():
    owf = simple_owf(7)
    assert "output" in owf
    _has_steps(owf)

    prg = simple_prg("0a", output_bits=8)
    assert len(prg["output_bits"]) == 8
    _has_steps(prg)

    prf = simple_prf("0a0b", "1011")
    assert "output" in prf
    _has_steps(prf)

    enc = cpa_encrypt("0a0b", "hello")
    dec = cpa_decrypt("0a0b", enc["r"], enc["ciphertext"])
    assert dec["plaintext"] == "hello"

    cbc = cbc_encrypt("0a0b", b"hello", "00000001")
    cbc_dec = cbc_decrypt("0a0b", cbc["result"]["ciphertext"], "00000001")
    assert cbc_dec["result"]["plaintext"] == "hello"

    ctr = ctr_crypt("0a0b", b"hello", "00000001")
    assert "output_hex" in ctr["result"]

    ofb = ofb_crypt("0a0b", b"hello", "00000001")
    assert "output_hex" in ofb["result"]

    mac = prf_mac("0a0b", "hello")
    assert verify_prf_mac("0a0b", "hello", mac["tag"])["valid"] is True

    cbc_tag = cbc_mac("0a0b", "hello")
    assert verify_cbc_mac("0a0b", "hello", cbc_tag["tag"])["valid"] is True

    cca = cca_encrypt_then_mac("0a0b", "0a0b", "hello")
    cca_dec = cca_decrypt_then_verify("0a0b", "0a0b", cca["result"]["r"], cca["result"]["ciphertext"], cca["result"]["tag"])
    assert cca_dec["result"]["accepted"] is True

    md = toy_hash("hello")
    assert "digest" in md

    dlp = dlp_hash("hello")
    assert "digest" in dlp["result"]

    bday = birthday_collision_attack(truncate_bits=8, max_trials=2000)
    assert "found" in bday["result"]

    hmac = toy_hmac("0a0b", "hello")
    assert "tag" in hmac["result"]


def test_pa11_to_pa20_smoke():
    dh = diffie_hellman_exchange()
    assert dh["result"]["consistent"] is True

    rsa_keys = rsa_keygen(bits=32)["result"]
    pub = rsa_keys["public_key"]
    priv = rsa_keys["private_key"]

    rsa_ct = rsa_encrypt(42, pub["n"], pub["e"])["result"]["ciphertext"]
    rsa_pt = rsa_decrypt(rsa_ct, priv["n"], priv["d"], priv["p"], priv["q"])["result"]["plaintext"]
    assert rsa_pt == 42

    mr = miller_rabin_test(97)
    assert mr["result"]["is_probable_prime"] is True

    crt = crt_combine(2, 3, 3, 5)
    assert crt["result"]["x"] % 3 == 2
    assert crt["result"]["x"] % 5 == 3

    sig = rsa_sign("hello", pub["n"], priv["d"])["result"]["signature"]
    assert rsa_verify("hello", sig, pub["n"], pub["e"])["result"]["valid"] is True

    eg = elgamal_keygen(bits=16)["result"]
    eg_pub = eg["public_key"]
    eg_priv = eg["private_key"]
    eg_ct = elgamal_encrypt(7, eg_pub["p"], eg_pub["g"], eg_pub["y"])["result"]["ciphertext"]
    eg_pt = elgamal_decrypt(eg_ct["c1"], eg_ct["c2"], eg_pub["p"], eg_priv["x"])["result"]["plaintext"]
    assert eg_pt == 7

    ot = simplified_ot_send_receive(10, 20, 1)
    assert ot["result"]["received_message"] == 20

    and_gate = secure_and_gate(1, 1)
    assert and_gate["result"]["and"] == 1

    mpc = two_party_compute_and(1, 0)
    assert mpc["result"]["and"] == 0


def test_build_and_reduce_column_flow_smoke():
    artifact = build_primitive("DLP", "PRG", "0a")
    assert artifact["artifact"]

    reduce = execute_reduction("DLP", "PRG", "PRF", "0a", "1011")
    assert reduce["chain"] == ["DLP", "PRG", "PRF"]
    assert "result" in reduce["output"]
