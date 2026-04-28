"""Execute source->target reduction (Leg 2) using built primitive artifact."""

import hashlib
import json

from backend.core.builder import build_primitive
from backend.core.pa10_hmac.hmac import mac_to_crhf_via_hmac, toy_hmac
from backend.core.pa11_dh.diffie_hellman import diffie_hellman_exchange
from backend.core.pa12_rsa.rsa import rsa_keygen
from backend.core.pa15_signatures.signatures import rsa_sign
from backend.core.pa18_ot.ot import bellare_micali_ot
from backend.core.pa1_owf_prg.owf import simple_owf
from backend.core.pa1_owf_prg.prg import prg_as_owf, simple_prg
from backend.core.pa2_prf.ggm_prf import prg_from_prf, simple_prf
from backend.core.pa3_cpa_enc.enc import cpa_encrypt
from backend.core.pa4_modes.cbc import cbc_encrypt
from backend.core.pa4_modes.ctr import ctr_crypt
from backend.core.pa4_modes.ofb import ofb_crypt
from backend.core.pa6_cca.cca_enc import cca_encrypt_then_mac
from backend.core.pa5_mac.prf_mac import prf_mac
from backend.core.pa7_md.merkle_damgard import toy_hash
from backend.core.pa8_dlp_hash.dlp_hash import dlp_hash
from backend.core.pa20_mpc.mpc import two_party_compute_and
from backend.core.reductions import reduce as reduce_route

DEFAULT_QUERY_BITS = "1011"
OWF_MODULUS = 2147483647

# Targets that encrypt/sign/hash/exercise the student's Message field directly. After a PRG→PRF
# hop, chaining would otherwise pass the serialized PRF dict into CTR/CBC/etc., producing ciphertext
# that ignores the plaintext message typed in Column 2.
_USE_MESSAGE_AS_PLAINTEXT = frozenset(
    {"CBC", "CTR", "OFB", "ENC", "CCA", "PRP", "MAC", "CRHF", "HASH", "DLPHASH", "HMAC"}
)

PRIMITIVE_NAME_ALIASES = {
    "ENCRYPTION": "ENC",
    "ENCRYPT": "ENC",
    "CPA": "ENC",
    "HASH": "CRHF",
    "DLPHASH": "CRHF",
    "DLP HASH": "CRHF",
    "CCA ENCRYPTION": "CCA",
    "PUBLIC KEY": "PKC",
    "PUBLIC KEY CRYPTOGRAPHY": "PKC",
    "SIGNATURE": "SIGN",
}


def _derive_hex_key(artifact: object, fallback_seed: str) -> str:
    artifact_text = str(artifact or "")
    candidate = "".join(ch for ch in artifact_text.lower().replace("0x", "") if ch in "0123456789abcdef")
    if candidate:
        if len(candidate) % 2:
            candidate = f"0{candidate}"
        return candidate[:64]
    digest = hashlib.sha256(f"{fallback_seed}:{artifact_text}".encode("utf-8")).hexdigest()
    return digest[:64]


def _normalize_primitive_name(name: str) -> str:
    normalized = " ".join((name or "").upper().replace("-", " ").replace("_", " ").split())
    return PRIMITIVE_NAME_ALIASES.get(normalized, normalized)


def _serialize_payload(value: object) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)


def _extract_query_bits(payload: object) -> str:
    bits = "".join(ch for ch in _serialize_payload(payload) if ch in {"0", "1"})
    return bits or DEFAULT_QUERY_BITS


def _hash_to_owf_input(payload: str) -> int:
    return int(hashlib.sha256(payload.encode("utf-8")).hexdigest(), 16) % OWF_MODULUS


def _run_step(target_primitive: str, derived_key: str, current_input: object) -> dict:
    target_upper = _normalize_primitive_name(target_primitive)
    current_text = _serialize_payload(current_input)

    if target_upper == "OWF":
        x = _hash_to_owf_input(current_text)
        return simple_owf(x)
    if target_upper == "OWP":
        # OWP: apply PRG to produce hard-core bits, using OWF/DLP approach
        owp_output = simple_prg(_derive_hex_key(current_text, derived_key), output_bits=32)
        return {
            "result": {"owp_output": owp_output["output_hex"], "note": "OWP via length-preserving PRG application"},
            "steps": ["OWP step: apply PRG in length-preserving mode (injective on range).", *owp_output["steps"]],
        }
    if target_upper == "PRG":
        return simple_prg(_derive_hex_key(current_text, derived_key), output_bits=32)
    if target_upper == "PRF":
        return simple_prf(derived_key, _extract_query_bits(current_input))
    if target_upper == "ENC":
        enc = cpa_encrypt(derived_key, current_text)
        return {"result": {"r": enc["r"], "ciphertext": enc["ciphertext"]}, "steps": enc["steps"]}
    if target_upper == "MAC":
        mac = prf_mac(derived_key, current_text)
        return {"result": {"tag": mac["tag"]}, "steps": mac["steps"]}
    if target_upper == "PRP":
        return cbc_encrypt(derived_key, current_text.encode("utf-8"), "00000001")
    if target_upper == "CBC":
        return cbc_encrypt(derived_key, current_text.encode("utf-8"), "00000001")
    if target_upper == "CTR":
        return ctr_crypt(derived_key, current_text.encode("utf-8"), "00000001")
    if target_upper == "OFB":
        return ofb_crypt(derived_key, current_text.encode("utf-8"), "00000001")
    if target_upper == "CCA":
        return cca_encrypt_then_mac(derived_key, derived_key, current_text)
    if target_upper == "CRHF":
        md = toy_hash(current_text)
        return {"result": {"digest": md["digest"]}, "steps": md["steps"]}
    if target_upper == "DLPHASH":
        return dlp_hash(current_text)
    if target_upper == "HMAC":
        return toy_hmac(derived_key, current_text)
    if target_upper == "PKC":
        return rsa_keygen(bits=32)
    if target_upper == "RSA":
        return rsa_keygen(bits=32)
    if target_upper == "DH":
        return diffie_hellman_exchange()
    if target_upper == "SIGN":
        key_bundle = rsa_keygen(bits=32)["result"]
        return rsa_sign(current_text, key_bundle["private_key"]["n"], key_bundle["private_key"]["d"])
    if target_upper == "OT":
        # Demo OT: sender messages are (0, 1), receiver choice derived from payload bit
        message_bytes = current_text.encode("utf-8")
        choice_bit = sum(message_bytes) % 2
        ot_result = bellare_micali_ot(m0=0, m1=1, choice_bit=choice_bit)
        return {
            "result": {
                "choice_bit": choice_bit,
                "received_message": ot_result["result"]["received_message"],
            },
            "steps": ["PA#18 OT: sender holds (m0=0, m1=1); receiver choice bit derived from input.", *ot_result["steps"]],
        }
    if target_upper == "MPC":
        message_bytes = current_text.encode("utf-8")
        # Reduce arbitrary payload into two deterministic demo bits for the 2PC AND primitive.
        bit_a = len(message_bytes) % 2
        bit_b = sum(message_bytes) % 2
        return two_party_compute_and(bit_a, bit_b)
    return {
        "result": {"input": current_text, "derived_key": derived_key},
        "steps": [f"No executor mapping for target primitive '{target_primitive}'."],
    }


def _run_transition(from_primitive: str, to_primitive: str, derived_key: str, current_input: object) -> dict:
    """Execute transition-specific reductions, including assignment-required backward edges."""
    from_upper = _normalize_primitive_name(from_primitive)
    to_upper = _normalize_primitive_name(to_primitive)
    current_text = _serialize_payload(current_input)

    if from_upper == "PRG" and to_upper == "OWF":
        return prg_as_owf(_derive_hex_key(current_text, derived_key))

    if from_upper == "PRF" and to_upper == "PRG":
        return prg_from_prf(derived_key)

    if from_upper == "MAC" and to_upper == "CRHF":
        return mac_to_crhf_via_hmac(derived_key, "cv", current_text)

    return _run_step(to_primitive, derived_key, current_input)


def execute_reduction(
    foundation: str,
    source_primitive: str,
    target_primitive: str,
    seed: str,
    message: str,
    reduction_mode: str = "forward",
) -> dict:
    """Build A then execute reduction route A->...->B sequentially."""
    build_result = build_primitive(foundation, source_primitive, seed)
    try:
        reduction_steps = reduce_route(source_primitive, target_primitive, mode=reduction_mode)
    except TypeError:
        # Compatibility fallback for monkeypatched tests that provide a 2-arg fake function.
        reduction_steps = reduce_route(source_primitive, target_primitive)
    source_upper = _normalize_primitive_name(source_primitive)
    target_upper = _normalize_primitive_name(target_primitive)
    derived_key = _derive_hex_key(build_result.get("artifact"), seed)
    route_output_steps: list[dict[str, object]] = []
    current_input: object = message

    if source_upper != target_upper and not reduction_steps:
        return {
            "build_steps": build_result["steps"],
            "reduction_steps": reduction_steps,
            "chain": [foundation.upper(), source_primitive.upper(), target_primitive.upper()],
            "output": {
                "result": {"artifact_from_column_1": build_result.get("artifact"), "derived_key": derived_key},
                "steps": [],
            },
        }

    if reduction_steps and reduction_steps[0].get("method") == "Identity":
        identity_output = {
            "result": {"artifact_from_column_1": build_result.get("artifact"), "input": current_input},
            "steps": ["Identity reduction step."],
        }
        route_output_steps.append(
            {
                "from": reduction_steps[0]["from"],
                "to": reduction_steps[0]["to"],
                "output": identity_output,
            }
        )
        final_output = identity_output
    else:
        final_output = {
            "result": {"artifact_from_column_1": build_result.get("artifact"), "derived_key": derived_key},
            "steps": [],
        }
        for step in reduction_steps:
            to_norm = _normalize_primitive_name(step["to"])
            run_input = message if to_norm in _USE_MESSAGE_AS_PLAINTEXT else current_input

            step_output = _run_transition(step["from"], step["to"], derived_key, run_input)
            route_output_steps.append({"from": step["from"], "to": step["to"], "output": step_output})
            current_input = step_output.get("result", step_output)
            final_output = step_output

    return {
        "build_steps": build_result["steps"],
        "reduction_steps": reduction_steps,
        "chain": [foundation.upper(), source_primitive.upper(), target_primitive.upper()],
        "output": {"result": final_output.get("result", final_output), "steps": route_output_steps},
    }
