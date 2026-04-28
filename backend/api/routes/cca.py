"""CCA endpoint for Encrypt-then-MAC demo."""

from fastapi import APIRouter, HTTPException

from backend.api.models import CCARequest
from backend.core.pa6_cca.cca_enc import cca_decrypt_then_verify, cca_encrypt_then_mac

router = APIRouter()


@router.post("/cca")
def cca_endpoint(payload: CCARequest) -> dict:
    """Run CCA encrypt/decrypt operation."""
    try:
        if payload.operation == "encrypt":
            if payload.message is None:
                raise ValueError("message is required for encrypt operation")
            return cca_encrypt_then_mac(payload.key_enc, payload.key_mac, payload.message)

        if not payload.r or not payload.ciphertext or not payload.tag:
            raise ValueError("r, ciphertext, and tag are required for decrypt operation")
        return cca_decrypt_then_verify(payload.key_enc, payload.key_mac, payload.r, payload.ciphertext, payload.tag)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
