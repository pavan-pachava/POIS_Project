"""RSA endpoint for keygen/encryption/decryption demos."""

from fastapi import APIRouter, HTTPException

from backend.api.models import RSARequest
from backend.core.pa12_rsa.rsa import rsa_decrypt, rsa_encrypt, rsa_keygen

router = APIRouter()


@router.post("/rsa")
def rsa_endpoint(payload: RSARequest) -> dict:
    """Run RSA operation with step tracing."""
    try:
        if payload.operation == "keygen":
            return rsa_keygen(bits=payload.bits)

        if payload.operation == "encrypt":
            if payload.message_int is None or payload.n is None or payload.e is None:
                raise ValueError("message_int, n, and e are required for encrypt")
            return rsa_encrypt(payload.message_int, payload.n, payload.e)

        if payload.ciphertext_int is None or payload.n is None or payload.d is None:
            raise ValueError("ciphertext_int, n, and d are required for decrypt")
        return rsa_decrypt(payload.ciphertext_int, payload.n, payload.d, payload.p, payload.q)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
