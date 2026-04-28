from backend.api.models import BuildRequest, CpaAttackRequest, ElGamalRequest, IvReuseAttackRequest, MalleabilityAttackRequest, ReduceRequest
from backend.api.routes.attacks import cpa_attack_endpoint, iv_reuse_endpoint, malleability_endpoint
from backend.api.routes.build import build_endpoint
from backend.api.routes.elgamal import elgamal_endpoint
from backend.api.routes.reduce import reduce_endpoint


def test_build_endpoint_exposes_result_and_steps():
    payload = BuildRequest(foundation="AES", source_primitive="PRG", seed="0a")
    response = build_endpoint(payload)

    assert "result" in response
    assert "steps" in response
    assert isinstance(response["steps"], list)
    assert "artifact" in response["result"]


def test_reduce_endpoint_exposes_result_and_steps():
    payload = ReduceRequest(
        foundation="AES",
        source_primitive="PRG",
        target_primitive="PRF",
        seed="0a",
        message="1011",
    )
    response = reduce_endpoint(payload)

    assert "result" in response
    assert "steps" in response
    assert isinstance(response["steps"], list)
    assert "output" in response
    assert "result" in response["output"]


def test_elgamal_endpoint_exposes_result_and_steps():
    payload = ElGamalRequest(operation="keygen", bits=16, g=2)
    response = elgamal_endpoint(payload)

    assert "result" in response
    assert "steps" in response
    assert isinstance(response["steps"], list)
    assert "public_key" in response["result"]
    assert "private_key" in response["result"]


def test_cpa_attack_endpoint_exposes_result_and_steps():
    payload = CpaAttackRequest(key="1a2b3c4d", m0="left", m1="right", nonce=7, trials=5)
    response = cpa_attack_endpoint(payload)

    assert "result" in response
    assert "steps" in response
    assert isinstance(response["steps"], list)
    assert "challenge_ciphertext" in response["result"]
    assert "success_rate" in response["result"]


def test_iv_reuse_endpoint_exposes_result_and_steps():
    payload = IvReuseAttackRequest(
        key="1a2b3c4d",
        known_plaintext="known-prefix-plaintext",
        target_plaintext="target-prefix-secret",
        nonce=7,
    )
    response = iv_reuse_endpoint(payload)

    assert "result" in response
    assert "steps" in response
    assert isinstance(response["steps"], list)
    assert "ciphertext_1" in response["result"]
    assert "recovered_target_prefix" in response["result"]


def test_malleability_endpoint_exposes_result_and_steps():
    payload = MalleabilityAttackRequest(key="1a2b3c4d", plaintext="pay=100", flip_mask_hex="01", nonce=9)
    response = malleability_endpoint(payload)

    assert "result" in response
    assert "steps" in response
    assert isinstance(response["steps"], list)
    assert "original_plaintext" in response["result"]
    assert "modified_plaintext" in response["result"]
