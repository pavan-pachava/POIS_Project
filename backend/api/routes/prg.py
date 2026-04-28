"""PRG route."""

from fastapi import APIRouter

from backend.api.models import PRGRequest
from backend.core.pa1_owf_prg.prg import simple_prg

router = APIRouter()


@router.post("/prg")
def prg_endpoint(payload: PRGRequest) -> dict:
    """Compute toy PRG output and steps."""
    result = simple_prg(payload.seed, payload.output_bits, payload.g, payload.p)
    return {"result": {"output_bits": result["output_bits"], "output_hex": result["output_hex"]}, "steps": result["steps"]}
