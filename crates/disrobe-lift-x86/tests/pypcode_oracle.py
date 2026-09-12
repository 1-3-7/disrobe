from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import sys

import pypcode


LANGUAGE = "x86:LE:64:default"
VERSION = "4.0.0"
LITTLE_ENDIAN = True
ADDRESS_SIZE = 8


@dataclass(frozen=True)
class Expression:
    kind: str
    values: tuple[object, ...]


def node_key(node: object) -> tuple[str, int, int]:
    return node.space.name, node.offset, node.size


def node_expression(node: object, size: int | None = None) -> Expression:
    node_size = ADDRESS_SIZE if node.space.name == "ram" and size is None else node.size
    return Expression(
        "node",
        (node.space.name, node.offset, node_size if size is None else size),
    )


def constant(value: int, size: int) -> Expression:
    mask = (1 << (size * 8)) - 1 if size < 8 else (1 << 64) - 1
    return Expression("node", ("const", value & mask, size))


def render(expression: Expression) -> str:
    if expression.kind == "node":
        space, offset, size = expression.values
        return f"{space}:0x{offset:x}:{size}"
    if expression.kind == "load":
        space, pointer, size = expression.values
        return f"load({space},{render(pointer)},{size})"
    if expression.kind == "select":
        condition, when_true, when_false = expression.values
        return f"select({render(condition)},{render(when_true)},{render(when_false)})"
    if len(expression.values) == 1:
        return f"{expression.kind}({render(expression.values[0])})"
    left, right = expression.values
    return f"{expression.kind}({render(left)},{render(right)})"


def constant_value(expression: Expression) -> tuple[int, int] | None:
    if expression.kind != "node" or expression.values[0] != "const":
        return None
    return int(expression.values[1]), int(expression.values[2])


def binary(
    name: str,
    left: Expression,
    right: Expression,
    commutative: bool,
    output_size: int,
) -> Expression:
    if name == "add":
        return canonical_add(left, right, output_size)
    if name == "subpiece":
        left_node = left.values if left.kind == "node" else None
        right_constant = constant_value(right)
        if (
            left_node is not None
            and left_node[0] == "register"
            and right_constant is not None
            and right_constant[0] + output_size <= left_node[2]
        ):
            return Expression(
                "node",
                (
                    "register",
                    left_node[1] + right_constant[0],
                    output_size,
                ),
            )
    if (
        name == "booland"
        and left.kind == "boolnot"
        and right.kind == "boolnot"
    ):
        disjunction = binary(
            "boolor",
            left.values[0],
            right.values[0],
            True,
            output_size,
        )
        return Expression("boolnot", (disjunction,))
    if name in {"shl", "lshr", "ashr"}:
        right_constant = constant_value(right)
        if right_constant is not None:
            right = constant(right_constant[0], 4)
    left_constant = constant_value(left)
    right_constant = constant_value(right)
    if left_constant is not None and right_constant is not None:
        left_value = left_constant[0]
        right_value = right_constant[0]
        if name == "add":
            return constant(left_value + right_value, output_size)
        if name == "sub":
            return constant(left_value - right_value, output_size)
        if name == "mul":
            return constant(left_value * right_value, output_size)
        if name == "and":
            return constant(left_value & right_value, output_size)
        if name == "or":
            return constant(left_value | right_value, output_size)
        if name == "xor":
            return constant(left_value ^ right_value, output_size)
        if name in {"eq", "ne", "ult", "slt"}:
            if name == "eq":
                result = left_value == right_value
            elif name == "ne":
                result = left_value != right_value
            elif name == "ult":
                result = left_value < right_value
            else:
                bits = output_size * 8
                sign = 1 << (bits - 1)
                signed_left = left_value - (1 << bits) if left_value & sign else left_value
                signed_right = right_value - (1 << bits) if right_value & sign else right_value
                result = signed_left < signed_right
            return constant(int(result), output_size)
        if name in {"booland", "boolor", "boolxor"}:
            if name == "booland":
                result = bool(left_value) and bool(right_value)
            elif name == "boolor":
                result = bool(left_value) or bool(right_value)
            else:
                result = bool(left_value) != bool(right_value)
            return constant(int(result), output_size)
    if render(left) == render(right):
        if name in {"eq"}:
            return constant(1, output_size)
        if name in {"ne", "sub", "xor", "boolxor"}:
            return constant(0, output_size)
    if left_constant is not None:
        if name in {"mul", "and", "booland"} and left_constant[0] == 0:
            return constant(0, output_size)
        if name == "mul" and left_constant[0] == 1:
            return right
        if name == "and" and left_constant[0] == (1 << (output_size * 8)) - 1:
            return right
        if name in {"or", "xor", "boolor", "boolxor"} and left_constant[0] == 0:
            return right
        if name == "boolor" and left_constant[0] != 0:
            return constant(1, output_size)
    if right_constant is not None:
        if name in {"mul", "and", "booland"} and right_constant[0] == 0:
            return constant(0, output_size)
        if name == "mul" and right_constant[0] == 1:
            return left
        if name == "and" and right_constant[0] == (1 << (output_size * 8)) - 1:
            return left
        if name in {"or", "xor", "boolor", "boolxor"} and right_constant[0] == 0:
            return left
        if name == "boolor" and right_constant[0] != 0:
            return constant(1, output_size)
    if commutative and render(left) > render(right):
        left, right = right, left
    return Expression(name, (left, right))


def unary(name: str, value: Expression, output_size: int) -> Expression:
    source = constant_value(value)
    if source is not None and name == "zext":
        return constant(source[0], output_size)
    if source is not None and name == "not":
        return constant(~source[0], output_size)
    if source is not None and name == "boolnot":
        return constant(int(source[0] == 0), output_size)
    if name == "boolnot" and value.kind == "boolnot":
        return value.values[0]
    return Expression(name, (value,))


def select(
    condition: Expression,
    when_true: Expression,
    when_false: Expression,
) -> Expression:
    if condition.kind == "boolnot":
        return Expression(
            "select",
            (condition.values[0], when_false, when_true),
        )
    return Expression("select", (condition, when_true, when_false))


def canonical_add(
    left: Expression,
    right: Expression,
    output_size: int,
) -> Expression:
    terms: list[Expression] = []
    constant_total = 0
    saw_constant = False

    def collect(expression: Expression) -> None:
        nonlocal constant_total, saw_constant
        value = constant_value(expression)
        if value is not None:
            constant_total += value[0]
            saw_constant = True
            return
        if expression.kind == "add":
            collect(expression.values[0])
            collect(expression.values[1])
            return
        terms.append(expression)

    collect(left)
    collect(right)
    mask = (1 << (output_size * 8)) - 1 if output_size < 8 else (1 << 64) - 1
    constant_total &= mask
    if saw_constant and (constant_total != 0 or not terms):
        terms.append(constant(constant_total, output_size))
    terms.sort(key=render)
    if not terms:
        return constant(0, output_size)
    result = terms[0]
    for term in terms[1:]:
        result = Expression("add", (result, term))
    return result


def architectural_register(node: object) -> bool:
    if node.space.name != "register":
        return False
    name = node.getRegisterName()
    return xmm_base(node) is not None or name in {
        "RAX", "RBX", "RCX", "RDX", "RSP", "RBP", "RSI", "RDI",
        "EAX", "EBX", "ECX", "EDX", "ESP", "EBP", "ESI", "EDI",
        "AX", "BX", "CX", "DX", "SP", "BP", "SI", "DI",
        "AL", "BL", "CL", "DL", "AH", "BH", "CH", "DH",
    } or re.fullmatch(r"R(?:8|9|1[0-5])(?:D|W|B)?", name) is not None


def xmm_base(node: object) -> int | None:
    if node.space.name != "register" or node.offset < 0x1200:
        return None
    index = (node.offset - 0x1200) // 0x40
    if index >= 16:
        return None
    base = 0x1200 + index * 0x40
    within = node.offset - base
    if within + node.size > 16:
        return None
    return base


def gpr_base(node: object) -> int | None:
    if node.space.name != "register":
        return None
    bases = tuple(range(0x00, 0x40, 8)) + tuple(range(0x80, 0xC0, 8))
    for base in bases:
        if base <= node.offset and node.offset + node.size <= base + 8:
            return base
    return None


def boolean_register(node: object) -> bool:
    return node.space.name == "register" and node.getRegisterName() in {
        "AF",
        "CF",
        "OF",
        "PF",
        "SF",
        "ZF",
    }


def normalize(operations: list[object], mnemonic: str) -> list[str]:
    values: dict[tuple[str, int, int], Expression] = {}
    facts: list[str] = []
    pending_facts: list[str] = []
    pending_condition: Expression | None = None

    def flush_facts() -> None:
        pending_facts.sort()
        facts.extend(pending_facts)
        pending_facts.clear()

    def resolve(node: object) -> Expression:
        exact = values.get(node_key(node))
        if exact is not None:
            return exact
        if node.space.name != "unique":
            return node_expression(node)
        node_start = node.offset
        node_end = node.offset + node.size
        candidates = [
            (key, expression)
            for key, expression in values.items()
            if key[0] == "unique"
            and key[1] <= node_start
            and node_end <= key[1] + key[2]
        ]
        if not candidates:
            return node_expression(node)
        key, expression = min(candidates, key=lambda item: item[0][2])
        byte_offset = (
            node_start - key[1]
            if LITTLE_ENDIAN
            else key[1] + key[2] - node_end
        )
        return Expression(
            "subpiece",
            (expression, constant(byte_offset, 4)),
        )

    def record(output: object, expression: Expression) -> None:
        nonlocal pending_condition
        key = node_key(output)
        if pending_condition is not None:
            previous = values.get(key, node_expression(output))
            expression = select(pending_condition, previous, expression)
            pending_condition = None
        values[key] = expression
        if output.space.name == "register":
            register_name = output.getRegisterName()
            if register_name in {"CF", "PF", "ZF", "SF", "OF"}:
                marker = f"write_flag({register_name})"
                pending_facts[:] = [fact for fact in pending_facts if fact != marker]
                identity = expression == node_expression(output)
                if expression.kind == "and":
                    left, right = expression.values
                    identity = identity or (
                        constant_value(left) == (1, 1) and right == node_expression(output)
                    ) or (
                        constant_value(right) == (1, 1) and left == node_expression(output)
                    )
                if not identity:
                    pending_facts.append(marker)
                return
        if architectural_register(output):
            fact_output = node_expression(output)
            fact_expression = expression
            general_base = gpr_base(output)
            fact_size = output.size
            if general_base is not None and output.size == 4 and output.offset == general_base:
                fact_output = Expression("node", ("register", general_base, 8))
                fact_expression = unary("zext", expression, 8)
                values[("register", general_base, 8)] = fact_expression
                fact_size = 8
            if fact_size == 8 and general_base is not None:
                partial_prefixes = {
                    f"write(register:0x{general_base:x}:{size},"
                    for size in (1, 2, 4)
                }
                pending_facts[:] = [
                    fact
                    for fact in pending_facts
                    if not any(fact.startswith(prefix) for prefix in partial_prefixes)
                ]
            vector_base = xmm_base(output)
            if vector_base is not None and output.size == 16:
                partial_prefixes = {
                    f"write(register:0x{vector_base + byte_offset:x}:{size},"
                    for byte_offset in range(16)
                    for size in (1, 2, 4, 8)
                    if byte_offset + size <= 16
                }
                pending_facts[:] = [
                    fact
                    for fact in pending_facts
                    if not any(fact.startswith(prefix) for prefix in partial_prefixes)
                ]
            prefix = f"write({render(fact_output)},"
            pending_facts[:] = [
                fact for fact in pending_facts if not fact.startswith(prefix)
            ]
            pending_facts.append(f"{prefix}{render(fact_expression)})")

    binary_names = {
        "BOOL_AND": ("booland", True),
        "BOOL_OR": ("boolor", True),
        "BOOL_XOR": ("boolxor", True),
        "FLOAT_ADD": ("fadd", True),
        "FLOAT_DIV": ("fdiv", False),
        "FLOAT_EQUAL": ("feq", True),
        "FLOAT_LESS": ("flt", False),
        "FLOAT_LESSEQUAL": ("fle", False),
        "FLOAT_MULT": ("fmul", True),
        "FLOAT_SUB": ("fsub", False),
        "INT_ADD": ("add", True),
        "INT_AND": ("and", True),
        "INT_CARRY": ("carry", True),
        "INT_DIV": ("udiv", False),
        "INT_EQUAL": ("eq", True),
        "INT_LEFT": ("shl", False),
        "INT_LESS": ("ult", False),
        "INT_MULT": ("mul", True),
        "INT_NOTEQUAL": ("ne", True),
        "INT_OR": ("or", True),
        "INT_REM": ("urem", False),
        "INT_RIGHT": ("lshr", False),
        "INT_SBORROW": ("sborrow", False),
        "INT_SCARRY": ("scarry", True),
        "INT_SDIV": ("sdiv", False),
        "INT_SLESS": ("slt", False),
        "INT_SREM": ("srem", False),
        "INT_SRIGHT": ("ashr", False),
        "INT_SUB": ("sub", False),
        "INT_XOR": ("xor", True),
    }
    unary_names = {
        "BOOL_NEGATE": "boolnot",
        "FLOAT_FLOAT2FLOAT": "float2float",
        "FLOAT_SQRT": "fsqrt",
        "FLOAT_INT2FLOAT": "int2float",
        "FLOAT_NAN": "fnan",
        "FLOAT_ROUND": "fround",
        "INT_NEGATE": "not",
        "INT_SEXT": "sext",
        "INT_ZEXT": "zext",
        "FLOAT_TRUNC": "trunc",
        "LZCOUNT": "lzcount",
        "POPCOUNT": "popcount",
    }
    for operation in operations:
        name = operation.opcode.name
        if name == "IMARK":
            continue
        if name == "CALLOTHER":
            continue
        if name == "COPY":
            record(operation.output, resolve(operation.inputs[0]))
            continue
        if name in binary_names:
            operation_name, commutative = binary_names[name]
            if (
                name == "INT_NOTEQUAL"
                and boolean_register(operation.inputs[0])
                and boolean_register(operation.inputs[1])
            ):
                operation_name = "boolxor"
            if (
                name == "INT_EQUAL"
                and boolean_register(operation.inputs[0])
                and boolean_register(operation.inputs[1])
            ):
                different = binary(
                    "boolxor",
                    resolve(operation.inputs[0]),
                    resolve(operation.inputs[1]),
                    True,
                    operation.output.size,
                )
                record(
                    operation.output,
                    unary("boolnot", different, operation.output.size),
                )
                continue
            record(
                operation.output,
                binary(
                    operation_name,
                    resolve(operation.inputs[0]),
                    resolve(operation.inputs[1]),
                    commutative,
                    operation.output.size,
                ),
            )
            continue
        if name in unary_names:
            record(
                operation.output,
                unary(
                    unary_names[name],
                    resolve(operation.inputs[0]),
                    operation.output.size,
                ),
            )
            continue
        if name in {"INT_LESSEQUAL", "INT_SLESSEQUAL"}:
            comparison_name = "ult" if name == "INT_LESSEQUAL" else "slt"
            comparison = binary(
                comparison_name,
                resolve(operation.inputs[1]),
                resolve(operation.inputs[0]),
                False,
                operation.output.size,
            )
            record(operation.output, Expression("boolnot", (comparison,)))
            continue
        if name == "LOAD":
            space = operation.inputs[0].getSpaceFromConst().name
            record(
                operation.output,
                Expression(
                    "load",
                    (space, resolve(operation.inputs[1]), operation.output.size),
                ),
            )
            continue
        if name == "SUBPIECE":
            record(
                operation.output,
                binary(
                    "subpiece",
                    resolve(operation.inputs[0]),
                    resolve(operation.inputs[1]),
                    False,
                    operation.output.size,
                ),
            )
            continue
        if name == "PIECE":
            record(
                operation.output,
                binary(
                    "piece",
                    resolve(operation.inputs[0]),
                    resolve(operation.inputs[1]),
                    False,
                    operation.output.size,
                ),
            )
            continue
        if name == "STORE":
            space = operation.inputs[0].getSpaceFromConst().name
            pending_facts.append(
                f"store({space},{render(resolve(operation.inputs[1]))},{render(resolve(operation.inputs[2]))})"
            )
            continue
        if name == "BRANCH":
            flush_facts()
            facts.append(f"branch({render(resolve(operation.inputs[0]))})")
            continue
        if name == "BRANCHIND":
            flush_facts()
            facts.append(f"branchind({render(resolve(operation.inputs[0]))})")
            continue
        if name == "CALL":
            flush_facts()
            facts.append(f"call({render(resolve(operation.inputs[0]))})")
            continue
        if name == "CALLIND":
            flush_facts()
            facts.append(f"callind({render(resolve(operation.inputs[0]))})")
            continue
        if name == "RETURN":
            flush_facts()
            facts.append(f"return({render(resolve(operation.inputs[0]))})")
            continue
        if name == "CBRANCH":
            target = operation.inputs[0]
            condition = resolve(operation.inputs[1])
            if mnemonic.startswith("cmov") or target.space.name == "const":
                pending_condition = condition
            else:
                flush_facts()
                facts.append(f"cbranch({render(resolve(target))},{render(condition)})")
            continue
        raise RuntimeError(f"unsupported pypcode operation {name}")
    if pending_condition is not None:
        raise RuntimeError("unresolved internal pypcode branch")
    flush_facts()
    return facts


def main() -> None:
    if pypcode.__version__ != VERSION:
        raise RuntimeError(f"pypcode {VERSION} required")
    if len(sys.argv) != 3:
        raise RuntimeError("usage: pypcode_oracle.py CORPUS OUTPUT")
    corpus = Path(sys.argv[1]).resolve(strict=True)
    output = Path(sys.argv[2]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    machine_code = (corpus / "x86_64_oracle_o2.text").read_bytes()
    records = []
    for line in (corpus / "x86_64_oracle_o2.boundaries").read_text(encoding="utf-8").splitlines()[1:]:
        address, length, mnemonic = line.split("\t")
        records.append((int(address, 16), int(length), mnemonic))
    context = pypcode.Context(LANGUAGE)
    raw_lines = [f"pypcode {VERSION}", LANGUAGE]
    table_lines = ["address\tbytes\tmnemonic\tnormalized_architectural_effects"]
    aliases = {
        "cmovc": "cmovb",
        "cmovna": "cmovbe",
        "cmovnbe": "cmova",
        "cmovnc": "cmovae",
        "cmovng": "cmovle",
        "cmovnge": "cmovl",
        "cmovnl": "cmovge",
        "cmovnle": "cmovg",
        "cmovnz": "cmovne",
        "cmovpe": "cmovp",
        "cmovpo": "cmovnp",
        "cmovz": "cmove",
        "jz": "je",
        "retn": "ret",
        "sal": "shl",
        "setc": "setb",
        "setna": "setbe",
        "setnbe": "seta",
        "setnc": "setae",
        "setng": "setle",
        "setnge": "setl",
        "setnl": "setge",
        "setnle": "setg",
        "setnz": "setne",
        "setpe": "setp",
        "setpo": "setnp",
        "setz": "sete",
    }
    for address, length, mnemonic in records:
        encoded = machine_code[address : address + length]
        if len(encoded) != length:
            raise RuntimeError(f"short instruction {address:x}")
        disassembly = context.disassemble(encoded, base_address=address, max_instructions=1)
        if len(disassembly.instructions) != 1:
            raise RuntimeError(f"disassembly count {address:x}")
        decoded = disassembly.instructions[0]
        observed_raw = decoded.mnem.lower()
        for suffix in (".lock", ".rep", ".repe", ".repne", ".repz", ".repnz"):
            if observed_raw.endswith(suffix):
                observed_raw = observed_raw.removesuffix(suffix)
                break
        observed = aliases.get(observed_raw, observed_raw)
        semantic_nop_alias = observed == "nop" and mnemonic == "xchg" and encoded == bytes.fromhex("6690")
        cmpsq_alias = observed == "cmpsd" and mnemonic == "cmpsq" and encoded.endswith(bytes.fromhex("48a7"))
        if decoded.length != length or (observed != mnemonic and not semantic_nop_alias and not cmpsq_alias):
            raise RuntimeError(
                f"disassembly mismatch {address:x}: {observed}/{decoded.length} != {mnemonic}/{length}"
            )
        translation = context.translate(
            encoded,
            base_address=address,
            max_instructions=1,
        )
        raw_lines.append(f"{address:x} {encoded.hex()} {mnemonic}")
        raw_lines.extend(str(translation).splitlines())
        facts = normalize(list(translation.ops), mnemonic)
        normalized = "|".join(facts) if facts else "none"
        table_lines.append(
            f"{address:x}\t{encoded.hex()}\t{mnemonic}\t{normalized}"
        )
    (output / "x86_64_pypcode.raw").write_text(
        "\n".join(raw_lines) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (output / "x86_64_pypcode.tsv").write_text(
        "\n".join(table_lines) + "\n",
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    main()
