"""PA#17: Encrypt-then-Sign with verify-before-decrypt CCA-secure PKC demos."""

import json
import random

from backend.core.pa12_rsa.rsa import rsa_keygen
from backend.core.pa15_signatures.signatures import rsa_sign, rsa_verify
from backend.core.pa16_elgamal.elgamal import (
    elgamal_decrypt,
    elgamal_encrypt,
    elgamal_keygen,
    elgamal_malleability_attack,
)


def _serialize_ciphertext(ciphertext: dict) -> str:
    return json.dumps(ciphertext, sort_keys=True)


def cca_pkc_keygen(bits: int = 64, elgamal_bits: int = 16) -> dict:
    """Generate encryption and signature key material for signcrypt flow."""
    enc = elgamal_keygen(bits=elgamal_bits)["result"]
    sig = rsa_keygen(bits=bits)["result"]
    return {
        "result": {
            "pk_enc": enc["public_key"],
            "sk_enc": enc["private_key"],
            "vk_sign": sig["public_key"],
            "sk_sign": sig["private_key"],
        },
        "steps": ["Generated ElGamal encryption keys and RSA signing keys"],
    }


def cca_pkc_encrypt_then_sign(pk_enc: dict, sk_sign: dict, message_int: int) -> dict:
    """Encrypt with ElGamal, then sign ciphertext with RSA signature."""
    enc = elgamal_encrypt(message_int % pk_enc["p"], pk_enc["p"], pk_enc["g"], pk_enc["y"])
    ciphertext = enc["result"]["ciphertext"]
    sig = rsa_sign(_serialize_ciphertext(ciphertext), sk_sign["n"], sk_sign["d"])
    return {
        "result": {
            "ciphertext": ciphertext,
            "signature": sig["result"]["signature"],
        },
        "steps": [
            "Step 1: Encrypt under ElGamal",
            *enc["steps"],
            "Step 2: Sign ciphertext under RSA hash-then-sign",
            *sig["steps"],
        ],
    }


def cca_pkc_verify_then_decrypt(sk_enc: dict, pk_enc: dict, vk_sign: dict, ciphertext: dict, signature: int) -> dict:
    """Verify signature first; only then decrypt. Invalid signature => reject."""
    verify = rsa_verify(_serialize_ciphertext(ciphertext), signature, vk_sign["n"], vk_sign["e"])
    steps = ["Verify signature before decrypt", *verify["steps"]]
    if not verify["result"]["valid"]:
        steps.append("Signature invalid, return bottom")
        return {"result": {"accepted": False, "plaintext": None}, "steps": steps}

    dec = elgamal_decrypt(ciphertext["c1"], ciphertext["c2"], pk_enc["p"], sk_enc["x"])
    steps.extend(["Signature valid, decrypt ciphertext", *dec["steps"]])
    return {"result": {"accepted": True, "plaintext": dec["result"]["plaintext"]}, "steps": steps}


def cca2_game_demo(message0: int, message1: int, bits: int = 64, elgamal_bits: int = 16) -> dict:
    """Simplified IND-CCA2 game for Encrypt-then-Sign construction."""
    keys = cca_pkc_keygen(bits=bits, elgamal_bits=elgamal_bits)["result"]
    b = random.randint(0, 1)
    challenge_message = message0 if b == 0 else message1

    challenge = cca_pkc_encrypt_then_sign(keys["pk_enc"], keys["sk_sign"], challenge_message)["result"]

    tampered_ciphertext = {
        "c1": challenge["ciphertext"]["c1"],
        "c2": (challenge["ciphertext"]["c2"] * 2) % keys["pk_enc"]["p"],
    }
    oracle_response = cca_pkc_verify_then_decrypt(
        keys["sk_enc"],
        keys["pk_enc"],
        keys["vk_sign"],
        tampered_ciphertext,
        challenge["signature"],
    )

    b_guess = random.randint(0, 1)
    return {
        "result": {
            "challenge_bit": b,
            "guess": b_guess,
            "guess_correct": b_guess == b,
            "tampered_oracle_response": oracle_response["result"],
        },
        "steps": [
            "Challenge generated using Encrypt-then-Sign",
            "Adversary tampers ciphertext and queries decryption oracle",
            *oracle_response["steps"],
            "Tampered query gets rejected before decrypt",
        ],
    }


def contrast_with_plain_elgamal(message_int: int, bits: int = 16) -> dict:
    """Contrast plain ElGamal malleability with PA17 verify-then-decrypt behavior."""
    enc_keys = elgamal_keygen(bits=bits)["result"]
    pk = enc_keys["public_key"]
    sk = enc_keys["private_key"]
    sig_keys = rsa_keygen(bits=64)["result"]

    plain_ciphertext = elgamal_encrypt(message_int % pk["p"], pk["p"], pk["g"], pk["y"])["result"]["ciphertext"]
    attacked = elgamal_malleability_attack(plain_ciphertext["c1"], plain_ciphertext["c2"], pk["p"]) ["result"]["modified_ciphertext"]
    plain_decrypted = elgamal_decrypt(attacked["c1"], attacked["c2"], pk["p"], sk["x"])["result"]["plaintext"]

    signcrypted = cca_pkc_encrypt_then_sign(pk, sig_keys["private_key"], message_int % pk["p"]) ["result"]
    tampered_sc = {
        "c1": signcrypted["ciphertext"]["c1"],
        "c2": (signcrypted["ciphertext"]["c2"] * 2) % pk["p"],
    }
    cca_result = cca_pkc_verify_then_decrypt(sk, pk, sig_keys["public_key"], tampered_sc, signcrypted["signature"]) ["result"]

    return {
        "result": {
            "plain_elgamal_tampered_plaintext": plain_decrypted,
            "cca_tampered_response": cca_result,
        },
        "steps": [
            "Plain ElGamal accepts malleated ciphertext and outputs transformed plaintext",
            "Encrypt-then-Sign rejects tampered ciphertext due to failed signature verification",
        ],
    }
