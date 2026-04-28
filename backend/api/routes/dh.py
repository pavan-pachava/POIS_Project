"""Diffie-Hellman endpoint."""

from fastapi import APIRouter, HTTPException

from backend.api.models import DHRequest
from backend.core.pa11_dh.diffie_hellman import diffie_hellman_exchange

router = APIRouter()


@router.post("/dh")
def dh_endpoint(payload: DHRequest) -> dict:
    """Run DH exchange simulation."""
    try:
        return diffie_hellman_exchange(payload.p, payload.g, payload.a, payload.b)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
