"""Bit and byte conversion helpers."""


def normalize_hex(value: str) -> str:
    value = value.strip().lower().replace("0x", "")
    if not value:
        return "00"
    if len(value) % 2:
        value = "0" + value
    return value


def hex_to_int(value: str) -> int:
    return int(normalize_hex(value), 16)


def int_to_hex(value: int, min_bytes: int = 1) -> str:
    hex_value = f"{value:x}"
    if len(hex_value) % 2:
        hex_value = "0" + hex_value
    needed = max(min_bytes * 2, len(hex_value))
    return hex_value.rjust(needed, "0")


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def hex_to_bytes(value: str) -> bytes:
    return bytes.fromhex(normalize_hex(value))


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def text_to_bytes(value: str) -> bytes:
    return value.encode("utf-8")


def bytes_to_bits(data: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in data)
