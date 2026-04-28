"""MPC endpoint for PA#18 OT, PA#19 gates, and PA#20 circuits."""

from fastapi import APIRouter, HTTPException

from backend.api.models import MPCRequest
from backend.core.pa20_mpc.mpc import (
    evaluate_addition,
    evaluate_equality,
    evaluate_millionaire,
    two_party_compute_and,
)
from backend.core.pa18_ot.ot import bellare_micali_ot
from backend.core.pa19_secure_and.secure_and import secure_and_gate, secure_not_gate, secure_xor_gate

router = APIRouter()


@router.post("/mpc")
def mpc_endpoint(payload: MPCRequest) -> dict:
    """Run selected MPC primitive."""
    try:
        if payload.operation == "ot":
            return bellare_micali_ot(
                m0=payload.m0,
                m1=payload.m1,
                choice_bit=payload.choice_bit,
                bits=payload.elgamal_bits,
                g=payload.elgamal_g,
            )
        if payload.operation == "and":
            return secure_and_gate(payload.a_bit, payload.b_bit)
        if payload.operation == "xor":
            return secure_xor_gate(payload.a_bit, payload.b_bit)
        if payload.operation == "not":
            return secure_not_gate(payload.a_bit)
        if payload.operation == "millionaire":
            return evaluate_millionaire(payload.x_value, payload.y_value, payload.bit_width)
        if payload.operation == "equality":
            return evaluate_equality(payload.x_value, payload.y_value, payload.bit_width)
        if payload.operation == "addition":
            return evaluate_addition(payload.x_value, payload.y_value, payload.bit_width)
        return two_party_compute_and(payload.a_bit, payload.b_bit)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
