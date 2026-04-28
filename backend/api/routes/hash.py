"""Hash endpoint."""

from fastapi import APIRouter, HTTPException

from backend.api.models import HashRequest
from backend.core.pa10_hmac.hmac import toy_hmac, verify_toy_hmac
from backend.core.pa7_md.merkle_damgard import toy_hash
from backend.core.pa8_dlp_hash.dlp_hash import dlp_hash
from backend.core.pa9_birthday.attack import birthday_collision_attack

router = APIRouter()


@router.post("/hash")
def hash_endpoint(payload: HashRequest) -> dict:
    """Compute hash-family outputs and steps."""
    try:
        scheme = payload.scheme.lower()
        if scheme == "md":
            result = toy_hash(payload.message)
            return {"result": {"digest": result["digest"]}, "steps": result["steps"]}
        if scheme == "dlp":
            return dlp_hash(payload.message)
        if scheme == "hmac":
            if not payload.key:
                raise ValueError("key is required for hmac scheme")
            if payload.tag:
                return verify_toy_hmac(payload.key, payload.message, payload.tag)
            return toy_hmac(payload.key, payload.message)
        if scheme == "birthday":
            return birthday_collision_attack(payload.truncate_bits, payload.max_trials)
        raise ValueError("Unsupported hash scheme")
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
