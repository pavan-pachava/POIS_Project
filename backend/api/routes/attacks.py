"""Attack demonstration endpoints."""

from fastapi import APIRouter, HTTPException

from backend.api.models import CpaAttackRequest, IvReuseAttackRequest, MalleabilityAttackRequest
from backend.core.pa3_cpa_enc.attacks import simulate_cpa_attack, simulate_malleability_attack, simulate_nonce_reuse_attack

router = APIRouter()


@router.post("/cpa-attack")
def cpa_attack_endpoint(payload: CpaAttackRequest) -> dict:
    """Run a toy IND-CPA attack simulation and return explanation steps."""
    try:
        return simulate_cpa_attack(
            payload.key,
            payload.m0,
            payload.m1,
            challenge_bit=payload.challenge_bit,
            reused_nonce=payload.nonce,
            trials=payload.trials,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@router.post("/iv-reuse")
def iv_reuse_endpoint(payload: IvReuseAttackRequest) -> dict:
    """Show leakage when IV/nonce is reused in stream-style encryption."""
    try:
        return simulate_nonce_reuse_attack(
            payload.key,
            known_plaintext=payload.known_plaintext,
            target_plaintext=payload.target_plaintext,
            reused_nonce=payload.nonce,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@router.post("/malleability")
def malleability_endpoint(payload: MalleabilityAttackRequest) -> dict:
    """Demonstrate controlled plaintext changes from ciphertext bit flipping."""
    try:
        return simulate_malleability_attack(
            payload.key,
            payload.plaintext,
            flip_mask_hex=payload.flip_mask_hex,
            reused_nonce=payload.nonce,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
