"""Reduction route for Leg 2 A->B."""

from fastapi import APIRouter

from backend.api.models import ReduceRequest
from backend.core.reduce_executor import execute_reduction

router = APIRouter()


@router.post("/reduce")
def reduce_endpoint(payload: ReduceRequest) -> dict:
    """Run reduction pipeline and return steps + output."""
    reduction = execute_reduction(
        payload.foundation,
        payload.source_primitive,
        payload.target_primitive,
        payload.seed,
        payload.message,
        payload.reduction_mode,
    )
    output = reduction.get("output") or {}
    return {
        **reduction,
        "result": output.get("result", output),
        "steps": output.get("steps", []),
    }
