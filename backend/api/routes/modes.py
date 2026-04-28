"""Modes endpoint for CBC/CTR/OFB demos."""

from fastapi import APIRouter, HTTPException

from backend.api.models import ModesRequest
from backend.core.pa4_modes.cbc import cbc_decrypt, cbc_encrypt
from backend.core.pa4_modes.ctr import ctr_crypt
from backend.core.pa4_modes.ofb import ofb_crypt
from backend.core.utils.bit_utils import bytes_to_hex, hex_to_bytes, text_to_bytes

router = APIRouter()


def _read_input(data: str, input_format: str) -> bytes:
    return hex_to_bytes(data) if input_format == "hex" else text_to_bytes(data)


@router.post("/modes")
def modes_endpoint(payload: ModesRequest) -> dict:
    """Run selected mode operation with tracing."""
    try:
        mode = payload.mode.lower()
        operation = payload.operation.lower()

        if mode == "cbc":
            if operation == "encrypt":
                return cbc_encrypt(payload.key, _read_input(payload.data, payload.input_format), payload.iv_or_nonce)
            return cbc_decrypt(payload.key, payload.data, payload.iv_or_nonce)

        if mode == "ctr":
            result = ctr_crypt(payload.key, _read_input(payload.data, payload.input_format), payload.iv_or_nonce)
            if operation == "decrypt":
                result["result"]["plaintext"] = hex_to_bytes(result["result"]["output_hex"]).decode("utf-8", errors="replace")
            return result

        if mode == "ofb":
            result = ofb_crypt(payload.key, _read_input(payload.data, payload.input_format), payload.iv_or_nonce)
            if operation == "decrypt":
                result["result"]["plaintext"] = hex_to_bytes(result["result"]["output_hex"]).decode("utf-8", errors="replace")
            return result

        raise ValueError("Unsupported mode. Use cbc, ctr, or ofb.")
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
