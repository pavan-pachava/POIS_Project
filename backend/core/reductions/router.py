"""Graph-based routing engine for primitive reductions."""

from collections import deque


GRAPH: dict[str, list[tuple[str, str]]] = {
    "OWF": [("PRG", "HILL hard-core-bit construction"), ("OWP", "DLP gives OWP: f(x)=g^x mod p")],
    "OWP": [("PRG", "OWP hard-core-bit construction: G(x)=(f(x),b(x))")],
    "PRG": [("PRF", "GGM")],
    "PRF": [
        ("PRP", "Domain-extension / switching"),
        ("MAC", "PRF-based MAC"),
        ("ENC", "PRF-based Encryption"),
        ("CBC", "CBC mode (toy block cipher from PRF)"),
        ("CTR", "CTR mode (toy counter mode from PRF)"),
        ("OFB", "OFB mode (toy output feedback from PRF)"),
    ],
    "PRP": [
        ("ENC", "Block-cipher mode construction"),
        ("MAC", "Block-cipher-based MAC"),
        ("CBC", "CBC mode with PRP as block cipher"),
        ("CTR", "CTR mode with PRP as block cipher"),
        ("OFB", "OFB mode with PRP as block cipher"),
    ],
    "MAC": [("CCA", "Encrypt-then-MAC transformation")],
    "ENC": [("CCA", "Authenticate encrypted channel")],
    "CRHF": [("HMAC", "Keyed hash wrapping")],
    "HMAC": [("MAC", "Use HMAC as a MAC")],
    "PKC": [("ENC", "Public-key to hybrid encryption"), ("SIGN", "Signature construction")],
    "RSA": [("PKC", "RSA public-key primitive")],
    "DH": [("PKC", "Diffie-Hellman key establishment to PKC")],
    "SIGN": [("OT", "PKC-based 1-out-of-2 Oblivious Transfer")],
    "OT": [("MPC", "OT-based secure AND/XOR gates compose any 2-party circuit")],
    "CCA": [],
    "MPC": [],
}

BACKWARD_ONLY_EDGES: dict[str, list[tuple[str, str]]] = {
    "PRG": [("OWF", "PRG as OWF (f(s)=G(s))"), ("OWP", "Length-preserving PRG is itself a OWP")],
    "PRF": [("PRG", "PRG from PRF: G(s)=F_s(0^n)||F_s(1^n)")],
    "MAC": [("CRHF", "MAC to CRHF via HMAC-based keyed compression")],
}

ALIASES = {
    "ENCRYPTION": "ENC",
    "ENCRYPT": "ENC",
    "CPA": "ENC",
    "CPA ENCRYPTION": "ENC",
    "CCA ENCRYPTION": "CCA",
    "CCA_ENCRYPTION": "CCA",
    "HASH": "CRHF",
    "MERKLE DAMGARD": "CRHF",
    "DLP HASH": "CRHF",
    "DLPHASH": "CRHF",
    "PUBLIC KEY CRYPTOGRAPHY": "PKC",
    "PUBLIC KEY": "PKC",
}

DISPLAY_NAME = {
    "ENC": "Encryption",
    "CCA": "CCA Encryption",
    "CRHF": "CRHF",
    "PKC": "PKC",
}


def _normalize_primitive_name(name: str) -> str:
    normalized = " ".join((name or "").upper().replace("-", " ").replace("_", " ").split())
    return ALIASES.get(normalized, normalized)


def _display(name: str) -> str:
    return DISPLAY_NAME.get(name, name)


def _graph_for_mode(mode: str) -> dict[str, list[tuple[str, str]]]:
    normalized_mode = (mode or "forward").lower()
    if normalized_mode == "forward":
        return GRAPH

    if normalized_mode == "backward":
        return BACKWARD_ONLY_EDGES

    if normalized_mode != "both":
        raise ValueError("mode must be one of: forward, backward, both")

    merged: dict[str, list[tuple[str, str]]] = {node: list(edges) for node, edges in GRAPH.items()}
    for node, edges in BACKWARD_ONLY_EDGES.items():
        merged.setdefault(node, [])
        merged[node].extend(edges)
    return merged


def reduce(source: str, target: str, mode: str = "forward") -> list[dict[str, str]]:
    """Return shortest supported reduction route from source to target."""
    source_node = _normalize_primitive_name(source)
    target_node = _normalize_primitive_name(target)

    if source_node == target_node:
        display = _display(source_node)
        return [{"from": display, "to": display, "step": f"{display} → {display}", "method": "Identity"}]

    graph = _graph_for_mode(mode)
    queue = deque([source_node])
    parents: dict[str, tuple[str, str] | None] = {source_node: None}

    while queue:
        node = queue.popleft()
        for nxt, method in graph.get(node, []):
            if nxt in parents:
                continue
            parents[nxt] = (node, method)
            if nxt == target_node:
                route: list[dict[str, str]] = []
                cursor = target_node
                while cursor != source_node:
                    parent = parents[cursor]
                    assert parent is not None, (
                        f"Internal error during reduction from {source_node} to {target_node}: "
                        f"node {cursor} should have a parent"
                    )
                    prev, edge_method = parent
                    from_name = _display(prev)
                    to_name = _display(cursor)
                    route.append({"from": from_name, "to": to_name, "step": f"{from_name} → {to_name}", "method": edge_method})
                    cursor = prev
                return list(reversed(route))
            queue.append(nxt)

    return []
