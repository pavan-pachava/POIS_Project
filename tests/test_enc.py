from backend.core.pa3_cpa_enc.dec import cpa_decrypt
from backend.core.pa3_cpa_enc.enc import cpa_encrypt


def test_encrypt_decrypt_roundtrip():
    key = "1a2b3c4d"
    message = "hello"
    enc = cpa_encrypt(key, message)
    dec = cpa_decrypt(key, enc["r"], enc["ciphertext"])
    assert dec["plaintext"] == message
