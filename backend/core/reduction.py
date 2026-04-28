"""Compatibility wrapper around unified reduction router."""

from backend.core.reductions.router import reduce as reduce_route


def reduce_primitives(source: str, target: str) -> list[str]:
    """Return readable legacy string chain for compatibility."""
    route = reduce_route(source, target)
    if not route:
        source_node = (source or "").upper()
        target_node = (target or "").upper()
        return [
            f"No supported forward reduction path from {source_node} to {target_node}.",
            "Try changing source/target or use the reverse direction in the UI.",
        ]
    return [f"{step['from']} -> {step['to']} via {step['method']}" for step in route]
