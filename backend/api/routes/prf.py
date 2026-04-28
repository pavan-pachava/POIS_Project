"""PRF route."""

from fastapi import APIRouter

from backend.api.models import PRFRequest
from backend.core.pa2_prf.ggm_prf import simple_prf

router = APIRouter()


@router.post("/prf")
def prf_endpoint(payload: PRFRequest) -> dict:
    """Compute toy PRF output and steps."""
    result = simple_prf(payload.key, payload.query)
    return {"result": {"output": result["output"], "query": result["query"]}, "steps": result["steps"]}
