"""PA#18: 1-out-of-2 OT using ElGamal-style PKC roles."""

import random

from backend.core.pa16_elgamal.elgamal import elgamal_decrypt, elgamal_encrypt, elgamal_keygen


def _validate_choice(choice_bit: int) -> None:
    if choice_bit not in (0, 1):
        raise ValueError("choice_bit must be 0 or 1")


def _normalize_message(value: int, modulus: int) -> int:
    return value % modulus


def ot_receiver_step1(choice_bit: int, bits: int = 16, g: int = 2) -> dict:
    """Receiver creates one honest key and one trapdoor-less random key."""
    _validate_choice(choice_bit)

    honest = elgamal_keygen(bits=bits, g=g)["result"]
    p = honest["public_key"]["p"]
    generator = honest["public_key"]["g"]
    honest_y = honest["public_key"]["y"]
    sk = honest["private_key"]["x"]
    random_y = random.randrange(2, p - 1)

    if choice_bit == 0:
        pk0 = {"p": p, "g": generator, "y": honest_y}
        pk1 = {"p": p, "g": generator, "y": random_y}
    else:
        pk0 = {"p": p, "g": generator, "y": random_y}
        pk1 = {"p": p, "g": generator, "y": honest_y}

    state = {
        "choice_bit": choice_bit,
        "p": p,
        "g": generator,
        "sk_choice": sk,
    }

    return {
        "result": {
            "pk0": pk0,
            "pk1": pk1,
            "state": state,
        },
        "steps": [
            f"Receiver choice b={choice_bit}",
            "Generate one honest ElGamal keypair for the chosen index.",
            f"Shared group parameters p={p}, g={generator}",
            "Construct the other public key as random group element (no trapdoor known).",
            "Send both (pk0, pk1) to sender; sender cannot distinguish which is honest.",
        ],
    }


def ot_sender_step(pk0: dict, pk1: dict, m0: int, m1: int) -> dict:
    """Sender encrypts each message under the corresponding receiver-provided key."""
    if not pk0 or not pk1:
        raise ValueError("pk0 and pk1 are required")

    p0 = int(pk0["p"])
    p1 = int(pk1["p"])
    if p0 != p1:
        raise ValueError("pk0 and pk1 must use the same modulus p")

    g0 = int(pk0["g"])
    g1 = int(pk1["g"])
    if g0 != g1:
        raise ValueError("pk0 and pk1 must use the same generator g")

    m0_mod = _normalize_message(int(m0), p0)
    m1_mod = _normalize_message(int(m1), p1)

    c0 = elgamal_encrypt(m0_mod, p0, g0, int(pk0["y"]))["result"]["ciphertext"]
    c1 = elgamal_encrypt(m1_mod, p1, g1, int(pk1["y"]))["result"]["ciphertext"]

    return {
        "result": {
            "c0": c0,
            "c1": c1,
            "normalized_messages": {"m0": m0_mod, "m1": m1_mod},
        },
        "steps": [
            f"Normalize m0,m1 modulo p: m0={m0_mod}, m1={m1_mod}",
            "Encrypt m0 under pk0 and m1 under pk1 via ElGamal.",
            "Return (C0, C1) to receiver.",
        ],
    }


def ot_receiver_step2(state: dict, c0: dict, c1: dict) -> dict:
    """Receiver decrypts only the selected ciphertext using the held secret key."""
    if not state:
        raise ValueError("state is required")

    _validate_choice(int(state["choice_bit"]))
    choice_bit = int(state["choice_bit"])
    p = int(state["p"])
    sk_choice = int(state["sk_choice"])

    selected_ciphertext = c0 if choice_bit == 0 else c1
    selected = elgamal_decrypt(
        int(selected_ciphertext["c1"]),
        int(selected_ciphertext["c2"]),
        p,
        sk_choice,
    )["result"]["plaintext"]

    return {
        "result": {
            "choice": choice_bit,
            "received_message": selected,
        },
        "steps": [
            f"Receiver picks ciphertext C{choice_bit}",
            f"Decrypt C{choice_bit} with sk_b to recover m_b={selected}",
            "No secret key exists for the non-chosen random public key.",
        ],
    }


def bellare_micali_ot(m0: int, m1: int, choice_bit: int, bits: int = 16, g: int = 2) -> dict:
    """Run complete 1-out-of-2 OT transcript with explicit receiver/sender roles."""
    step1 = ot_receiver_step1(choice_bit=choice_bit, bits=bits, g=g)
    state = step1["result"]["state"]
    pk0 = step1["result"]["pk0"]
    pk1 = step1["result"]["pk1"]

    step_sender = ot_sender_step(pk0=pk0, pk1=pk1, m0=m0, m1=m1)
    c0 = step_sender["result"]["c0"]
    c1 = step_sender["result"]["c1"]

    step2 = ot_receiver_step2(state=state, c0=c0, c1=c1)
    received = step2["result"]["received_message"]

    return {
        "result": {
            "choice": choice_bit,
            "received_message": received,
            "pk0": pk0,
            "pk1": pk1,
            "c0": c0,
            "c1": c1,
        },
        "steps": [
            "Receiver Step1: create (pk0, pk1) with one honest and one random-trapdoorless key.",
            *step1["steps"],
            "Sender Step: encrypt both messages under the provided keys.",
            *step_sender["steps"],
            "Receiver Step2: decrypt only selected branch.",
            *step2["steps"],
            "Receiver privacy: sender cannot tell which key was honest.",
            "Sender privacy: receiver only has sk for one branch.",
        ],
    }


def simplified_ot_send_receive(m0: int, m1: int, choice_bit: int) -> dict:
    """Backward-compatible wrapper now backed by PA#18 OT implementation."""
    return bellare_micali_ot(m0=m0, m1=m1, choice_bit=choice_bit)
