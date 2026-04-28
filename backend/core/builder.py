"""Build Foundation -> Source primitive (Leg 1)."""

from backend.core.foundations.aes import AESFoundation
from backend.core.foundations.dlp import DLPFoundation
from backend.core.pa10_hmac.hmac import toy_hmac
from backend.core.pa11_dh.diffie_hellman import diffie_hellman_exchange
from backend.core.pa12_rsa.rsa import rsa_keygen
from backend.core.pa15_signatures.signatures import rsa_sign
from backend.core.pa18_ot.ot import simplified_ot_send_receive
from backend.core.pa1_owf_prg.prg import simple_prg
from backend.core.pa2_prf.ggm_prf import simple_prf
from backend.core.pa3_cpa_enc.enc import cpa_encrypt
from backend.core.pa4_modes.cbc import cbc_encrypt
from backend.core.pa4_modes.ctr import ctr_crypt
from backend.core.pa4_modes.ofb import ofb_crypt
from backend.core.pa5_mac.prf_mac import prf_mac
from backend.core.pa6_cca.cca_enc import cca_encrypt_then_mac
from backend.core.pa7_md.merkle_damgard import toy_hash
from backend.core.pa8_dlp_hash.dlp_hash import dlp_hash
from backend.core.pa20_mpc.mpc import two_party_compute_and


def build_primitive(foundation: str, source_primitive: str, seed: str) -> dict:
    """Build a source primitive instance from selected foundation and return steps."""
    foundation_upper = foundation.upper()
    source_upper = source_primitive.upper()
    steps = [f"Foundation selected: {foundation_upper}"]

    if foundation_upper == "AES":
        foundation_obj = AESFoundation()
    elif foundation_upper == "DLP":
        foundation_obj = DLPFoundation()
    else:
        raise ValueError(f"Unsupported foundation '{foundation}'. Use AES or DLP.")

    if source_upper == "OWF":
        result = foundation_obj.as_owf(seed)
        steps.extend(result["steps"])
        return {"artifact": result["value"], "steps": steps}

    if source_upper == "OWP":
        if foundation_upper == "DLP":
            result = foundation_obj.as_owp(seed)
            steps.extend(["DLP foundation: g^x mod p is a one-way permutation (OWP).", *result["steps"]])
            return {"artifact": result["value"], "steps": steps}
        # AES foundation: treat PRP evaluation on seed as OWP (PRP is a special OWP)
        result = foundation_obj.as_prp(seed, seed[:8] if len(seed) >= 8 else seed.ljust(8, "0"))
        steps.extend(["AES foundation: AES itself is a OWP (it is a PRP, hence bijective).", *result["steps"]])
        return {"artifact": result["output"], "steps": steps}

    if source_upper == "PRG":
        if foundation_upper == "AES":
            left = foundation_obj.as_prf(seed, "0")
            right = foundation_obj.as_prf(seed, "1")
            artifact = f"{left['output']}{right['output']}"
            steps.extend(
                [
                    "AES foundation: instantiate PRF first.",
                    f"F_k(0) = {left['output']}",
                    f"F_k(1) = {right['output']}",
                    f"PRG(s) = F_k(0)||F_k(1) = {artifact}",
                ]
            )
            return {"artifact": artifact, "steps": steps}

        dlp_owf = foundation_obj.as_owf(seed)
        prg_result = simple_prg(dlp_owf["value"], output_bits=32)
        steps.extend(["DLP OWF -> PRG via iterative hard-core-bit extraction", *prg_result["steps"]])
        return {"artifact": prg_result["output_hex"], "steps": steps}

    if source_upper == "PRF":
        if foundation_upper == "AES":
            result = foundation_obj.as_prf(seed, "1011")
            steps.extend(["AES directly provides PRF-like oracle", *result["steps"]])
            return {"artifact": result["output"], "steps": steps}

        prg_result = simple_prg(seed, output_bits=32)
        prf_result = simple_prf(prg_result["output_hex"], "1011")
        steps.extend(["DLP -> PRG", *prg_result["steps"], "PRG -> PRF (GGM-like)", *prf_result["steps"]])
        return {"artifact": prf_result["output"], "steps": steps}

    if source_upper == "MAC":
        mac_result = prf_mac(seed, "demo")
        steps.extend(["Build PRF first, then MAC", *mac_result["steps"]])
        return {"artifact": mac_result["tag"], "steps": steps}

    if source_upper == "ENC":
        enc_result = cpa_encrypt(seed, "demo")
        steps.extend(["Build PRF, then CPA encryption demo.", *enc_result["steps"]])
        return {"artifact": f"{enc_result['r']}:{enc_result['ciphertext']}", "steps": steps}

    if source_upper == "CBC":
        mode_result = cbc_encrypt(seed, b"demo", "00000001")
        steps.extend(["Instantiate CBC from toy block primitive.", *mode_result["steps"]])
        return {"artifact": mode_result["result"]["ciphertext"], "steps": steps}

    if source_upper == "CTR":
        mode_result = ctr_crypt(seed, b"demo", "00000001")
        steps.extend(["Instantiate CTR from toy PRF keystream.", *mode_result["steps"]])
        return {"artifact": mode_result["result"]["output_hex"], "steps": steps}

    if source_upper == "OFB":
        mode_result = ofb_crypt(seed, b"demo", "00000001")
        steps.extend(["Instantiate OFB from toy PRF feedback stream.", *mode_result["steps"]])
        return {"artifact": mode_result["result"]["output_hex"], "steps": steps}

    if source_upper == "CCA":
        cca_result = cca_encrypt_then_mac(seed, seed, "demo")
        steps.extend(["Compose CPA encryption and MAC (Encrypt-then-MAC).", *cca_result["steps"]])
        return {"artifact": str(cca_result["result"]), "steps": steps}

    if source_upper == "HASH":
        md_result = toy_hash("demo")
        steps.extend(md_result["steps"])
        return {"artifact": md_result["digest"], "steps": steps}

    if source_upper == "DLPHASH":
        dlp_result = dlp_hash("demo")
        steps.extend(dlp_result["steps"])
        return {"artifact": dlp_result["result"]["digest"], "steps": steps}

    if source_upper == "HMAC":
        hmac_result = toy_hmac(seed, "demo")
        steps.extend(hmac_result["steps"])
        return {"artifact": hmac_result["result"]["tag"], "steps": steps}

    if source_upper == "RSA":
        rsa_result = rsa_keygen(bits=32)
        steps.extend(rsa_result["steps"])
        return {"artifact": str(rsa_result["result"]["public_key"]), "steps": steps}

    if source_upper == "DH":
        dh_result = diffie_hellman_exchange()
        steps.extend(dh_result["steps"])
        return {"artifact": str(dh_result["result"]["shared_secret"]), "steps": steps}

    if source_upper == "MPC":
        mpc_result = two_party_compute_and(1, 1)
        steps.extend(mpc_result["steps"])
        return {"artifact": str(mpc_result["result"]["and"]), "steps": steps}

    if source_upper in {"SIGN", "SIGNATURE"}:
        rsa_result = rsa_keygen(bits=32)
        priv = rsa_result["result"]["private_key"]
        sign_result = rsa_sign("demo", priv["n"], priv["d"])
        steps.extend(["Generate RSA key pair, then sign demo message.", *rsa_result["steps"], *sign_result["steps"]])
        return {"artifact": str(sign_result["result"]["signature"]), "steps": steps}

    if source_upper == "OT":
        ot_result = simplified_ot_send_receive(m0=0, m1=1, choice_bit=1)
        steps.extend(["PA#18 OT demo: sender holds (0,1), receiver picks bit=1.", *ot_result["steps"]])
        received = ot_result["result"]["received_message"]
        return {"artifact": str(received), "steps": steps}

    return {
        "artifact": "",
        "steps": [
            *steps,
            f"{source_upper} is not implemented yet (placeholder).",
        ],
    }
