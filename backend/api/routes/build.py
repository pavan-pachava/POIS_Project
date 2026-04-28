"""Build route for Leg 1 Foundation->A."""

from fastapi import APIRouter

from backend.api.models import BuildRequest
from backend.core.builder import build_primitive

router = APIRouter()


@router.post("/build")
def build_endpoint(payload: BuildRequest) -> dict:
    """Build source primitive from foundation with steps."""
    build_data = build_primitive(payload.foundation, payload.source_primitive, payload.seed)
    return {
        "foundation": payload.foundation,
        "source_primitive": payload.source_primitive,
        "artifact": build_data["artifact"],
        "result": {"artifact": build_data["artifact"]},
        "steps": build_data["steps"],
    }
