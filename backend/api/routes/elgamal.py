"""ElGamal endpoint for PA#16 keygen/encryption/decryption demos."""

from fastapi import APIRouter, HTTPException

from backend.api.models import ElGamalRequest
from backend.core.pa16_elgamal.elgamal import elgamal_decrypt, elgamal_encrypt, elgamal_keygen

router = APIRouter()


@router.post("/elgamal")
def elgamal_endpoint(payload: ElGamalRequest) -> dict:
    """Run ElGamal operation with step tracing."""
    try:
        if payload.operation == "keygen":
            return elgamal_keygen(bits=payload.bits, g=payload.g)

        if payload.operation == "encrypt":
            if payload.message_int is None or payload.p is None or payload.g is None or payload.y is None:
                raise ValueError("message_int, p, g, and y are required for encrypt")
            return elgamal_encrypt(payload.message_int, payload.p, payload.g, payload.y)

        if payload.operation == "decrypt":
            if payload.c1 is None or payload.c2 is None or payload.p is None or payload.x is None:
                raise ValueError("c1, c2, p, and x are required for decrypt")
            return elgamal_decrypt(payload.c1, payload.c2, payload.p, payload.x)

        raise ValueError(f"Unsupported operation '{payload.operation}'")
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
