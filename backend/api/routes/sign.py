"""Digital signature endpoint."""

from fastapi import APIRouter, HTTPException

from backend.api.models import SignRequest
from backend.core.pa15_signatures.signatures import (
    elgamal_sign,
    elgamal_verify,
    rsa_sign,
    rsa_verify,
)

router = APIRouter()


@router.post("/sign")
def sign_endpoint(payload: SignRequest) -> dict:
    """Run signature sign/verify for RSA and ElGamal."""
    try:
        if payload.scheme == "rsa":
            if payload.operation == "sign":
                if payload.n is None or payload.d is None:
                    raise ValueError("n and d are required for RSA sign")
                return rsa_sign(payload.message, payload.n, payload.d)
            if payload.signature is None or payload.n is None or payload.e is None:
                raise ValueError("signature, n, and e are required for RSA verify")
            return rsa_verify(payload.message, payload.signature, payload.n, payload.e)

        if payload.operation == "sign":
            if payload.p is None or payload.g is None or payload.x is None:
                raise ValueError("p, g, and x are required for ElGamal sign")
            return elgamal_sign(payload.message, payload.p, payload.g, payload.x)

        if (
            payload.signature_r is None
            or payload.signature_s is None
            or payload.p is None
            or payload.g is None
            or payload.y is None
        ):
            raise ValueError("signature_r, signature_s, p, g, and y are required for ElGamal verify")
        return elgamal_verify(payload.message, payload.signature_r, payload.signature_s, payload.p, payload.g, payload.y)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
