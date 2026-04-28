"""Core MAC service orchestration shared by API routes."""

from backend.core.pa5_mac.cbc_mac import cbc_mac, verify_cbc_mac
from backend.core.pa5_mac.prf_mac import prf_mac, verify_prf_mac


def handle_mac(key: str, message: str, scheme: str = "prf", tag: str | None = None) -> dict:
    """Generate or verify MAC tags for supported schemes.

    Args:
        key: Secret key in the expected hex/text format used by MAC primitives.
        message: Input message to authenticate.
        scheme: MAC scheme selector ("prf" or "cbc").
        tag: Optional tag. When provided, verification mode is used.

    Returns:
        A result dictionary returned by the underlying MAC generation or verification function.
    """
    scheme_lower = scheme.lower()
    if scheme_lower not in {"prf", "cbc"}:
        raise ValueError(f"Unsupported MAC scheme '{scheme}'. Use 'prf' or 'cbc'.")

    if tag:
        if scheme_lower == "cbc":
            result = verify_cbc_mac(key, message, tag)
            return {"result": {k: v for k, v in result.items() if k != "steps"}, "steps": result["steps"]}
        result = verify_prf_mac(key, message, tag)
        return {"result": {k: v for k, v in result.items() if k != "steps"}, "steps": result["steps"]}

    if scheme_lower == "cbc":
        result = cbc_mac(key, message)
        return {"result": {k: v for k, v in result.items() if k != "steps"}, "steps": result["steps"]}
    result = prf_mac(key, message)
    return {"result": {k: v for k, v in result.items() if k != "steps"}, "steps": result["steps"]}
