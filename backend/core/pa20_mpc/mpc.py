"""PA#20: Generic circuit-based secure 2-party computation."""

from dataclasses import dataclass

from backend.core.pa19_secure_and.secure_and import secure_and_from_ot, secure_not_gate, secure_xor_gate


def _validate_bit(value: int, name: str) -> None:
    if value not in (0, 1):
        raise ValueError(f"{name} must be 0 or 1")


def int_to_bits(value: int, width: int) -> list[int]:
    if width <= 0:
        raise ValueError("width must be positive")
    mask = (1 << width) - 1
    value &= mask
    return [(value >> i) & 1 for i in range(width)]


def bits_to_int(bits: list[int]) -> int:
    out = 0
    for index, bit in enumerate(bits):
        _validate_bit(bit, f"bits[{index}]")
        out |= (bit << index)
    return out


@dataclass
class Gate:
    out: int
    op: str
    in1: int | None = None
    in2: int | None = None
    value: int | None = None


class Circuit:
    """Boolean circuit represented as a DAG over AND/XOR/NOT/CONST gates."""

    def __init__(self, alice_input_size: int, bob_input_size: int) -> None:
        if alice_input_size < 0 or bob_input_size < 0:
            raise ValueError("Input sizes must be non-negative")

        self.alice_input_size = alice_input_size
        self.bob_input_size = bob_input_size
        self.alice_inputs = list(range(alice_input_size))
        self.bob_inputs = list(range(alice_input_size, alice_input_size + bob_input_size))
        self._next_wire = alice_input_size + bob_input_size
        self.gates: list[Gate] = []
        self.outputs: list[int] = []

    def _new_wire(self) -> int:
        wire = self._next_wire
        self._next_wire += 1
        return wire

    def add_const(self, bit: int) -> int:
        _validate_bit(bit, "const")
        out = self._new_wire()
        self.gates.append(Gate(out=out, op="CONST", value=bit))
        return out

    def add_xor(self, in1: int, in2: int) -> int:
        out = self._new_wire()
        self.gates.append(Gate(out=out, op="XOR", in1=in1, in2=in2))
        return out

    def add_and(self, in1: int, in2: int) -> int:
        out = self._new_wire()
        self.gates.append(Gate(out=out, op="AND", in1=in1, in2=in2))
        return out

    def add_not(self, in1: int) -> int:
        out = self._new_wire()
        self.gates.append(Gate(out=out, op="NOT", in1=in1))
        return out

    def set_outputs(self, wires: list[int]) -> None:
        if not wires:
            raise ValueError("Circuit must expose at least one output wire")
        self.outputs = list(wires)


def _or_wire(circuit: Circuit, left: int, right: int) -> int:
    """x OR y = x XOR y XOR (x AND y)."""
    xor_lr = circuit.add_xor(left, right)
    and_lr = circuit.add_and(left, right)
    return circuit.add_xor(xor_lr, and_lr)


def secure_eval(circuit: Circuit, x_alice: list[int], y_bob: list[int]) -> dict:
    """Evaluate a boolean circuit using secure AND and free XOR/NOT gates."""
    if len(x_alice) != circuit.alice_input_size:
        raise ValueError("x_alice length does not match circuit alice_input_size")
    if len(y_bob) != circuit.bob_input_size:
        raise ValueError("y_bob length does not match circuit bob_input_size")

    for idx, bit in enumerate(x_alice):
        _validate_bit(bit, f"x_alice[{idx}]")
    for idx, bit in enumerate(y_bob):
        _validate_bit(bit, f"y_bob[{idx}]")

    wire_values: dict[int, int] = {}
    transcript: list[str] = []
    and_gate_calls = 0

    for index, bit in enumerate(x_alice):
        wire_values[circuit.alice_inputs[index]] = bit
    for index, bit in enumerate(y_bob):
        wire_values[circuit.bob_inputs[index]] = bit

    for gate_index, gate in enumerate(circuit.gates, start=1):
        if gate.op == "CONST":
            assert gate.value is not None
            wire_values[gate.out] = gate.value
            transcript.append(f"Gate {gate_index}: CONST -> wire {gate.out} = {gate.value}")
            continue

        if gate.in1 is None or gate.in1 not in wire_values:
            raise ValueError(f"Gate {gate_index} missing input wire in1")

        left = wire_values[gate.in1]

        if gate.op == "NOT":
            not_out = secure_not_gate(left)
            wire_values[gate.out] = not_out["result"]["not"]
            transcript.append(f"Gate {gate_index}: NOT(w{gate.in1}) -> w{gate.out}")
            transcript.extend(not_out["steps"])
            continue

        if gate.in2 is None or gate.in2 not in wire_values:
            raise ValueError(f"Gate {gate_index} missing input wire in2")

        right = wire_values[gate.in2]

        if gate.op == "XOR":
            xor_out = secure_xor_gate(left, right)
            wire_values[gate.out] = xor_out["result"]["xor"]
            transcript.append(f"Gate {gate_index}: XOR(w{gate.in1}, w{gate.in2}) -> w{gate.out}")
            transcript.extend(xor_out["steps"])
            continue

        if gate.op == "AND":
            and_gate_calls += 1
            and_out = secure_and_from_ot(left, right)
            wire_values[gate.out] = and_out["result"]["and"]
            transcript.append(f"Gate {gate_index}: AND(w{gate.in1}, w{gate.in2}) -> w{gate.out}")
            transcript.extend(and_out["steps"])
            continue

        raise ValueError(f"Unsupported gate operation '{gate.op}'")

    if not circuit.outputs:
        raise ValueError("Circuit has no output wires")

    output_bits = [wire_values[wire] for wire in circuit.outputs]
    return {
        "result": {
            "output_bits": output_bits,
            "output_value": bits_to_int(output_bits),
            "ot_calls": and_gate_calls,
        },
        "steps": transcript,
    }


def build_equality_circuit(width: int) -> Circuit:
    """Build a circuit for x == y over width bits."""
    circuit = Circuit(width, width)
    eq = circuit.add_const(1)
    for i in range(width):
        xor_bit = circuit.add_xor(circuit.alice_inputs[i], circuit.bob_inputs[i])
        xnor_bit = circuit.add_not(xor_bit)
        eq = circuit.add_and(eq, xnor_bit)
    circuit.set_outputs([eq])
    return circuit


def build_addition_circuit(width: int) -> Circuit:
    """Build ripple-carry adder for x + y (mod 2^width)."""
    circuit = Circuit(width, width)
    carry = circuit.add_const(0)
    sum_bits: list[int] = []

    for i in range(width):
        a_i = circuit.alice_inputs[i]
        b_i = circuit.bob_inputs[i]
        axb = circuit.add_xor(a_i, b_i)
        sum_i = circuit.add_xor(axb, carry)
        sum_bits.append(sum_i)

        c1 = circuit.add_and(a_i, b_i)
        c2 = circuit.add_and(carry, axb)
        carry = _or_wire(circuit, c1, c2)

    circuit.set_outputs(sum_bits)
    return circuit


def build_millionaire_circuit(width: int) -> Circuit:
    """Build comparator circuit that outputs 1 iff x > y."""
    circuit = Circuit(width, width)
    gt = circuit.add_const(0)
    eq = circuit.add_const(1)

    for i in range(width - 1, -1, -1):
        a_i = circuit.alice_inputs[i]
        b_i = circuit.bob_inputs[i]

        not_b = circuit.add_not(b_i)
        a_gt_b = circuit.add_and(a_i, not_b)
        eq_and_gt = circuit.add_and(eq, a_gt_b)
        gt = _or_wire(circuit, gt, eq_and_gt)

        xor_ab = circuit.add_xor(a_i, b_i)
        bit_eq = circuit.add_not(xor_ab)
        eq = circuit.add_and(eq, bit_eq)

    circuit.set_outputs([gt])
    return circuit


def evaluate_equality(x_value: int, y_value: int, width: int = 8) -> dict:
    circuit = build_equality_circuit(width)
    x_bits = int_to_bits(x_value, width)
    y_bits = int_to_bits(y_value, width)
    out = secure_eval(circuit, x_bits, y_bits)
    return {
        "result": {
            "x": x_value,
            "y": y_value,
            "width": width,
            "equal": bool(out["result"]["output_bits"][0]),
            "output_bits": out["result"]["output_bits"],
            "ot_calls": out["result"]["ot_calls"],
        },
        "steps": out["steps"],
    }


def evaluate_addition(x_value: int, y_value: int, width: int = 8) -> dict:
    circuit = build_addition_circuit(width)
    x_bits = int_to_bits(x_value, width)
    y_bits = int_to_bits(y_value, width)
    out = secure_eval(circuit, x_bits, y_bits)
    sum_value = out["result"]["output_value"]
    return {
        "result": {
            "x": x_value,
            "y": y_value,
            "width": width,
            "sum_mod_2n": sum_value,
            "output_bits": out["result"]["output_bits"],
            "ot_calls": out["result"]["ot_calls"],
        },
        "steps": out["steps"],
    }


def evaluate_millionaire(x_value: int, y_value: int, width: int = 8) -> dict:
    circuit = build_millionaire_circuit(width)
    x_bits = int_to_bits(x_value, width)
    y_bits = int_to_bits(y_value, width)
    out = secure_eval(circuit, x_bits, y_bits)
    richer = bool(out["result"]["output_bits"][0])
    return {
        "result": {
            "x": x_value,
            "y": y_value,
            "width": width,
            "x_gt_y": richer,
            "output_bits": out["result"]["output_bits"],
            "ot_calls": out["result"]["ot_calls"],
        },
        "steps": out["steps"],
    }


def two_party_compute_and(a_bit: int, b_bit: int) -> dict:
    """Backward-compatible wrapper for PA#20 smoke tests."""
    _validate_bit(a_bit, "a_bit")
    _validate_bit(b_bit, "b_bit")
    and_out = secure_and_from_ot(a_bit, b_bit)
    return {
        "result": {
            "a": a_bit,
            "b": b_bit,
            "and": and_out["result"]["and"],
        },
        "steps": and_out["steps"],
    }
