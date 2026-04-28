"""Encryption endpoint."""

from fastapi import APIRouter

from backend.api.models import EncryptRequest
from backend.core.pa3_enc.enc import cpa_encrypt

router = APIRouter()


@router.post("/encrypt")
def encrypt_endpoint(payload: EncryptRequest) -> dict:
    """Compute toy CPA encryption output and steps."""
    result = cpa_encrypt(payload.key, payload.message)
    return {"result": {"r": result["r"], "ciphertext": result["ciphertext"]}, "steps": result["steps"]}
