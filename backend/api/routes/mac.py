"""MAC route."""

from fastapi import APIRouter, HTTPException

from backend.api.models import MACRequest
from backend.core.pa5_mac.service import handle_mac

router = APIRouter()


@router.post("/mac")
def mac_endpoint(payload: MACRequest) -> dict:
    """Delegate MAC operation to core layer."""
    try:
        return handle_mac(payload.key, payload.message, payload.scheme, payload.tag)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
