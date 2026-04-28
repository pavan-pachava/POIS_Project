from backend.core.reductions import reduce
from backend.core import reduce_executor


def test_reduce_direct_prg_to_prf():
    assert reduce("PRG", "PRF") == [{"from": "PRG", "to": "PRF", "step": "PRG → PRF", "method": "GGM"}]


def test_reduce_multistep_owf_to_mac():
    assert reduce("OWF", "MAC") == [
        {"from": "OWF", "to": "PRG", "step": "OWF → PRG", "method": "HILL hard-core-bit construction"},
        {"from": "PRG", "to": "PRF", "step": "PRG → PRF", "method": "GGM"},
        {"from": "PRF", "to": "MAC", "step": "PRF → MAC", "method": "PRF-based MAC"},
    ]


def test_reduce_multistep_prf_to_cca_encryption():
    assert reduce("PRF", "CCA") == [
        {"from": "PRF", "to": "MAC", "step": "PRF → MAC", "method": "PRF-based MAC"},
        {"from": "MAC", "to": "CCA Encryption", "step": "MAC → CCA Encryption", "method": "Encrypt-then-MAC transformation"},
    ]


def test_reduce_direct_prp_to_mac():
    assert reduce("PRP", "MAC") == [
        {"from": "PRP", "to": "MAC", "step": "PRP → MAC", "method": "Block-cipher-based MAC"}
    ]


def test_reduce_direct_prf_to_cbc_ctr_ofb():
    assert reduce("PRF", "CBC") == [
        {"from": "PRF", "to": "CBC", "step": "PRF → CBC", "method": "CBC mode (toy block cipher from PRF)"}
    ]
    assert reduce("PRF", "CTR") == [
        {"from": "PRF", "to": "CTR", "step": "PRF → CTR", "method": "CTR mode (toy counter mode from PRF)"}
    ]
    assert reduce("PRF", "OFB") == [
        {"from": "PRF", "to": "OFB", "step": "PRF → OFB", "method": "OFB mode (toy output feedback from PRF)"}
    ]


def test_reduce_multistep_hash_to_mac_via_hmac():
    assert reduce("HASH", "MAC") == [
        {"from": "CRHF", "to": "HMAC", "step": "CRHF → HMAC", "method": "Keyed hash wrapping"},
        {"from": "HMAC", "to": "MAC", "step": "HMAC → MAC", "method": "Use HMAC as a MAC"},
    ]


def test_reduce_multistep_dh_to_sign_via_pkc():
    assert reduce("DH", "SIGN") == [
        {"from": "DH", "to": "PKC", "step": "DH → PKC", "method": "Diffie-Hellman key establishment to PKC"},
        {"from": "PKC", "to": "SIGN", "step": "PKC → SIGN", "method": "Signature construction"},
    ]


def test_reduce_identity_alias():
    assert reduce("ENC", "encryption") == [
        {"from": "Encryption", "to": "Encryption", "step": "Encryption → Encryption", "method": "Identity"}
    ]
    assert reduce("encryption", "ENCRYPT") == [
        {"from": "Encryption", "to": "Encryption", "step": "Encryption → Encryption", "method": "Identity"}
    ]
    assert reduce("PRF", "ENCRYPTION") == [
        {"from": "PRF", "to": "Encryption", "step": "PRF → Encryption", "method": "PRF-based Encryption"}
    ]


def test_reduce_unsupported_target():
    assert reduce("OWF", "DH") == []


def test_reduce_bidirectional_only_for_required_pairs():
    assert reduce("PRG", "OWF", mode="both") == [
        {"from": "PRG", "to": "OWF", "step": "PRG → OWF", "method": "PRG as OWF (f(s)=G(s))"}
    ]
    assert reduce("PRF", "PRG", mode="both") == [
        {
            "from": "PRF",
            "to": "PRG",
            "step": "PRF → PRG",
            "method": "PRG from PRF: G(s)=F_s(0^n)||F_s(1^n)",
        }
    ]
    assert reduce("MAC", "CRHF", mode="both") == [
        {
            "from": "MAC",
            "to": "CRHF",
            "step": "MAC → CRHF",
            "method": "MAC to CRHF via HMAC-based keyed compression",
        }
    ]


def test_reduce_non_required_backward_not_available():
    assert reduce("CCA", "ENC", mode="both") == []


def test_execute_reduction_runs_chain_sequentially(monkeypatch):
    def fake_build_primitive(foundation, source_primitive, seed):
        return {"artifact": "0abc", "steps": [f"built {foundation}:{source_primitive}:{seed}"]}

    def fake_reduce_route(source, target, mode="forward"):
        return [
            {"from": "A", "to": "X", "step": "A → X", "method": "m1"},
            {"from": "X", "to": "Y", "step": "X → Y", "method": "m2"},
            {"from": "Y", "to": "B", "step": "Y → B", "method": "m3"},
        ]

    run_inputs = []

    def fake_run_step(target_primitive, derived_key, current_input):
        run_inputs.append((target_primitive, derived_key, current_input))
        return {"result": {"target": target_primitive, "received": current_input}, "steps": [f"ran {target_primitive}"]}

    monkeypatch.setattr(reduce_executor, "build_primitive", fake_build_primitive)
    monkeypatch.setattr(reduce_executor, "reduce_route", fake_reduce_route)
    monkeypatch.setattr(reduce_executor, "_run_step", fake_run_step)

    response = reduce_executor.execute_reduction("DLP", "A", "B", "0a", "initial-input")
    step_outputs = response["output"]["steps"]

    assert len(step_outputs) == 3
    assert step_outputs[0]["from"] == "A"
    assert step_outputs[0]["to"] == "X"
    assert step_outputs[1]["from"] == "X"
    assert step_outputs[1]["to"] == "Y"
    assert step_outputs[2]["from"] == "Y"
    assert step_outputs[2]["to"] == "B"

    assert run_inputs[0][0] == "X"
    assert run_inputs[0][2] == "initial-input"
    assert run_inputs[1][0] == "Y"
    assert run_inputs[1][2] == step_outputs[0]["output"]["result"]
    assert run_inputs[2][0] == "B"
    assert run_inputs[2][2] == step_outputs[1]["output"]["result"]
    assert response["output"]["result"] == step_outputs[2]["output"]["result"]
