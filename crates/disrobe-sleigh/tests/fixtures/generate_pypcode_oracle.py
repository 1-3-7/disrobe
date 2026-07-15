from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

import pypcode


LANGUAGE = "AARCH64:LE:64:v8A"
VERSION = "4.0.0"


@dataclass(frozen=True)
class Expression:
    kind: str
    values: tuple[object, ...]


def node_key(node: object) -> tuple[str, int, int]:
    return node.space.name, node.offset, node.size


def node_expression(node: object, size: int | None = None) -> Expression:
    return Expression(
        "node",
        (node.space.name, node.offset, node.size if size is None else size),
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
    if commutative and render(left) > render(right):
        left, right = right, left
    return Expression(name, (left, right))


def unary(name: str, value: Expression, output_size: int) -> Expression:
    source = constant_value(value)
    if source is not None and name == "zext":
        return constant(source[0], output_size)
    if source is not None and name == "not":
        return constant(~source[0], output_size)
    return Expression(name, (value,))


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
    return name in {"NG", "ZR", "CY", "OV", "sp"} or re.fullmatch(r"x(?:[0-9]|[12][0-9]|30)", name) is not None


def normalize(operations: list[object]) -> list[str]:
    values: dict[tuple[str, int, int], Expression] = {}
    facts: list[str] = []
    pending_facts: list[str] = []
    pending_condition: Expression | None = None

    def flush_facts() -> None:
        pending_facts.sort()
        facts.extend(pending_facts)
        pending_facts.clear()

    def resolve(node: object) -> Expression:
        return values.get(node_key(node), node_expression(node))

    def record(output: object, expression: Expression) -> None:
        nonlocal pending_condition
        key = node_key(output)
        if pending_condition is not None and key in values:
            expression = Expression("select", (pending_condition, values[key], expression))
            pending_condition = None
        values[key] = expression
        if architectural_register(output):
            prefix = f"write({render(node_expression(output))},"
            pending_facts[:] = [
                fact for fact in pending_facts if not fact.startswith(prefix)
            ]
            pending_facts.append(f"{prefix}{render(expression)})")

    binary_names = {
        "BOOL_AND": ("booland", True),
        "BOOL_OR": ("boolor", True),
        "BOOL_XOR": ("boolxor", True),
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
        "INT_NEGATE": "not",
        "INT_SEXT": "sext",
        "INT_ZEXT": "zext",
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
            if target.space.name == "const":
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
    tests = Path(__file__).resolve().parent.parent
    corpus = tests / "corpus"
    machine_code = (corpus / "aarch64_forms.text").read_bytes()
    mnemonics = (corpus / "aarch64_forms.mnemonics").read_text(encoding="utf-8").split()
    instruction_count, remainder = divmod(len(machine_code), 4)
    if remainder != 0 or instruction_count != len(mnemonics):
        raise RuntimeError("assembly corpus length mismatch")
    context = pypcode.Context(LANGUAGE)
    raw_lines = [f"pypcode {VERSION}", LANGUAGE]
    table_lines = ["address\tword\tmnemonic\tnormalized_architectural_facts"]
    for index, mnemonic in enumerate(mnemonics):
        address = index * 4
        encoded = machine_code[address : address + 4]
        word = int.from_bytes(encoded, "little")
        translation = context.translate(encoded, base_address=address)
        raw_lines.append(f"{address:04x} {word:08x} {mnemonic}")
        raw_lines.extend(str(translation).splitlines())
        facts = normalize(list(translation.ops))
        normalized = "|".join(facts) if facts else "none"
        table_lines.append(
            f"{address:x}\t{word:08x}\t{mnemonic}\t{normalized}"
        )
    (corpus / "aarch64_pypcode.raw").write_text(
        "\n".join(raw_lines) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (corpus / "aarch64_pypcode.tsv").write_text(
        "\n".join(table_lines) + "\n",
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    main()
