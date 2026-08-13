"""Tier differential: what the strict tier catches that the normalized oracle accepts.

The recompile-equivalence oracle in py_arbitrary_measure.py grades a recovered code object
against a real CPython recompile through an opcode-normalized diff. That normalization is
deliberately lossy: it collapses every jump to a target-free JUMP token, it drops NOP-class
opcodes, and it pops the constant that feeds __firstlineno__/__static_attributes__. Anything
hidden by those rules can be lost by a recovery and still score as equivalent.

This harness measures the gap directly. Each case is a pair of real sources - an original and a
seeded recovery that exhibits one structural loss class - or a mutation applied to a real
compiled code object. Both sides are compiled by the running interpreter at an explicit optimize
level, then graded twice: once by the shipped normalized comparison (own_equiv) and once by the
shipped strict comparison (strict_diff_dimensions plus the co_firstlineno and co_positions legs).
Both graders are imported from py_arbitrary_measure, never reimplemented here, so a case that
comes back strict-only is evidence about the tier this repository ships.

Optimize level is passed to compile() explicitly rather than inherited from sys.flags, because -O
strips asserts and -OO strips docstrings: a recovery that always drops them scores perfectly when
the measurement is taken under the wrong flag, and the only way to show that is to measure the
same case under all three.

Usage:
    python py_tier_differential.py [--optimize-levels 0,1,2]
                                   [--require-version X.Y] [--require-magic HEX]

Emits a single JSON object on the first line of stdout and a readable table on stderr. It grades
nothing on its own: the expectations live in the Rust caller.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import types
from typing import Callable, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import py_arbitrary_measure as tier

MAX_CASES = 64
TARGET_NAME = "f"

JUMP_NEST_ORIGINAL = """
def f(a, b):
    if a:
        g()
    if b:
        g()
    return 1
"""
JUMP_NEST_RECOVERED = """
def f(a, b):
    if a:
        g()
        if b:
            g()
    return 1
"""

DOCSTRING_PRESENT = '''
def f(a):
    "recovered docstring"
    return a
'''
DOCSTRING_ABSENT = """
def f(a):
    # the docstring this recovery dropped
    return a
"""

ASSERT_PRESENT = """
def f(a):
    assert a
    return a
"""
ASSERT_ABSENT = """
def f(a):
    # the assert this recovery dropped
    return a
"""

ORDER_ORIGINAL = """
def f():
    x = 1
    y = 2
    return x, y
"""
ORDER_RECOVERED = """
def f():
    y = 2
    x = 1
    return x, y
"""

COMPREHENSION_ORIGINAL = """
def f(z):
    return [y for y in z]
"""
COMPREHENSION_RECOVERED = """
def f(z):
    out = []
    for y in z:
        out.append(y)
    return out
"""

LINE_ORIGINAL = """
def f(a):
    b = a + 1
    return b
"""
LINE_RECOVERED = """
def f(a):
    b = a + 1

    return b
"""

CONTROL_SOURCE = """
def f(a):
    b = a + 1
    return b
"""
CONTROL_COMMENTED = """
def f(a):
    b = a + 1  # a comment the original never carried
    return b
"""

MUTANT_BASE = """
def f(a, b):
    c = a + b
    return c
"""

Mutation = Callable[[types.CodeType], Tuple[Optional[types.CodeType], Optional[types.CodeType]]]


def target_of(source: str, optimize: int, filename: str) -> types.CodeType:
    module: types.CodeType = compile(
        source, filename, "exec", dont_inherit=True, optimize=optimize
    )
    for constant in module.co_consts:
        if isinstance(constant, types.CodeType) and constant.co_name == TARGET_NAME:
            return constant
    raise SystemExit(f"source compiled at optimize={optimize} carries no `{TARGET_NAME}`")


def mutate_stacksize(base: types.CodeType) -> tuple[types.CodeType, types.CodeType]:
    return base, base.replace(co_stacksize=base.co_stacksize + 1)


def mutate_flags(base: types.CodeType) -> tuple[types.CodeType, types.CodeType]:
    return base, base.replace(co_flags=base.co_flags ^ 0x20)


def mutate_names(base: types.CodeType) -> tuple[types.CodeType, types.CodeType]:
    return base, base.replace(co_names=base.co_names + ("unreferenced_name",))


def mutate_varnames(base: types.CodeType) -> tuple[types.CodeType, types.CodeType]:
    return base, base.replace(
        co_varnames=base.co_varnames + ("unreferenced_local",),
        co_nlocals=base.co_nlocals + 1,
    )


def mutate_consts_orphan(base: types.CodeType) -> tuple[types.CodeType, types.CodeType]:
    return base, base.replace(co_consts=base.co_consts + (987654,))


def mutate_consts_reorder(base: types.CodeType) -> tuple[types.CodeType, types.CodeType]:
    return (
        base.replace(co_consts=base.co_consts + (1001, 1002)),
        base.replace(co_consts=base.co_consts + (1002, 1001)),
    )


def mutate_argcount(base: types.CodeType) -> tuple[types.CodeType, types.CodeType]:
    return base, base.replace(co_argcount=base.co_argcount - 1)


def mutate_firstlineno(base: types.CodeType) -> tuple[types.CodeType, types.CodeType]:
    return base, base.replace(co_firstlineno=base.co_firstlineno + 1)


def mutate_qualname(base: types.CodeType) -> tuple[types.CodeType, types.CodeType]:
    return base, base.replace(co_qualname=base.co_qualname + "_renamed")


def mutate_exceptiontable(base: types.CodeType) -> tuple[types.CodeType, types.CodeType]:
    return base, base.replace(co_exceptiontable=b"\x81\x01\x01\x00")


PAIR_CASES = (
    ("jump_target_nesting", JUMP_NEST_ORIGINAL, JUMP_NEST_RECOVERED),
    ("docstring_dropped", DOCSTRING_PRESENT, DOCSTRING_ABSENT),
    ("docstring_invented", DOCSTRING_ABSENT, DOCSTRING_PRESENT),
    ("assert_dropped", ASSERT_PRESENT, ASSERT_ABSENT),
    ("statement_reorder", ORDER_ORIGINAL, ORDER_RECOVERED),
    ("comprehension_scope_collapsed", COMPREHENSION_ORIGINAL, COMPREHENSION_RECOVERED),
    ("line_shifted_body", LINE_ORIGINAL, LINE_RECOVERED),
    ("control_recompiled_twice", CONTROL_SOURCE, CONTROL_SOURCE),
    ("control_comment_only", CONTROL_SOURCE, CONTROL_COMMENTED),
)

MUTANT_CASES = (
    ("mutant_stacksize", mutate_stacksize),
    ("mutant_flags", mutate_flags),
    ("mutant_names_appended", mutate_names),
    ("mutant_varnames_appended", mutate_varnames),
    ("mutant_consts_orphan", mutate_consts_orphan),
    ("mutant_consts_reordered", mutate_consts_reorder),
    ("mutant_argcount", mutate_argcount),
    ("mutant_firstlineno", mutate_firstlineno),
    ("mutant_qualname", mutate_qualname),
    ("mutant_exceptiontable", mutate_exceptiontable),
)


def grade(name: str, kind: str, optimize: int, a: types.CodeType, b: types.CodeType) -> dict:
    normalized_ok, normalized_reason = tier.own_equiv(a, b)
    dimensions: list[str] = tier.strict_diff_dimensions(a, b)
    pairs, aligned, alignable = tier.align_positions(a, b)
    lines_ok: int = sum(1 for pa, pb in pairs if pa[0] == pb[0] and pa[1] == pb[1])
    full_scored: bool = not tier.is_no_debug_ranges(a)
    full_ok: int = sum(1 for pa, pb in pairs if pa == pb) if full_scored else 0
    return {
        "case": name,
        "kind": kind,
        "optimize": optimize,
        "available": 1,
        "unavailable_reason": "",
        "normalized_ok": int(normalized_ok),
        "normalized_reason": normalized_reason,
        "dimensions": dimensions,
        "firstlineno_equal": int(a.co_firstlineno == b.co_firstlineno),
        "position_lines_ok": lines_ok,
        "position_lines_total": len(pairs),
        "position_full_ok": full_ok,
        "position_full_total": len(pairs) if full_scored else 0,
        "position_aligned": aligned,
        "position_alignable": alignable,
        "inline_cache_units": tier.inline_cache_units(a),
        "unknown_opcode_units": tier.unknown_opcode_units(a) + tier.unknown_opcode_units(b),
    }


def unavailable(name: str, kind: str, optimize: int, reason: str) -> dict:
    return {
        "case": name,
        "kind": kind,
        "optimize": optimize,
        "available": 0,
        "unavailable_reason": reason,
        "normalized_ok": 0,
        "normalized_reason": "",
        "dimensions": [],
        "firstlineno_equal": 0,
        "position_lines_ok": 0,
        "position_lines_total": 0,
        "position_full_ok": 0,
        "position_full_total": 0,
        "position_aligned": 0,
        "position_alignable": 0,
        "inline_cache_units": 0,
        "unknown_opcode_units": 0,
    }


def run_pair(name: str, original: str, recovered: str, optimize: int) -> dict:
    a: types.CodeType = target_of(original, optimize, "<original>")
    b: types.CodeType = target_of(recovered, optimize, "<recovered>")
    return grade(name, "pair", optimize, a, b)


def run_mutant(name: str, mutation: Mutation, optimize: int) -> dict:
    base: types.CodeType = target_of(MUTANT_BASE, optimize, "<base>")
    try:
        a, b = mutation(base)
    except (AttributeError, TypeError, ValueError) as unsupported:
        return unavailable(
            name,
            "mutant",
            optimize,
            f"this interpreter cannot express the mutation: {unsupported}",
        )
    return grade(name, "mutant", optimize, a, b)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--optimize-levels", default="0,1,2")
    parser.add_argument("--require-version", default=None)
    parser.add_argument("--require-magic", default=None)
    arguments = parser.parse_args()

    refusal: Optional[str] = tier.interpreter_refusal(
        arguments.require_magic, arguments.require_version
    )
    if refusal is not None:
        print(refusal, file=sys.stderr)
        raise SystemExit(2)

    levels: list[int] = [
        int(piece) for piece in arguments.optimize_levels.split(",") if piece.strip()
    ]
    for level in levels:
        if level not in (0, 1, 2):
            raise SystemExit(f"optimize level {level} is outside the 0, 1, 2 CPython accepts")

    planned: int = len(levels) * (len(PAIR_CASES) + len(MUTANT_CASES))
    if planned > MAX_CASES:
        raise SystemExit(f"{planned} graded rows passes the {MAX_CASES} this harness bounds")

    rows: list[dict] = []
    for level in levels:
        for name, original, recovered in PAIR_CASES:
            rows.append(run_pair(name, original, recovered, level))
        for name, mutation in MUTANT_CASES:
            rows.append(run_mutant(name, mutation, level))

    probe: types.CodeType = target_of(MUTANT_BASE, 0, "<probe>")
    report = {
        "cpython_version": tier.running_version(),
        "cpython_release": sys.version.split()[0],
        "magic_number": tier.running_magic_hex(),
        "position_full_supported": int(tier.position_full_supported(probe)),
        "probe_inline_cache_units": tier.inline_cache_units(probe),
        "probe_unknown_opcode_units": tier.unknown_opcode_units(probe),
        "excluded_dimensions": ",".join(name for name, _ in tier.EXCLUDED_ATTRS),
        "byte_dimensions": ",".join(tier.BYTE_DIMENSIONS),
        "rows": rows,
    }
    print(json.dumps(report))

    print("\n=== tier differential ===", file=sys.stderr)
    for row in rows:
        if not row["available"]:
            print(
                f"  opt{row['optimize']} {row['case']:32} UNAVAILABLE "
                f"{row['unavailable_reason']}",
                file=sys.stderr,
            )
            continue
        verdict: str = "neither"
        strict_hit: bool = bool(row["dimensions"]) or (
            row["position_lines_ok"] != row["position_lines_total"]
        )
        if row["normalized_ok"] and strict_hit:
            verdict = "strict only"
        elif not row["normalized_ok"]:
            verdict = "both" if strict_hit else "normalized only"
        print(
            f"  opt{row['optimize']} {row['case']:32} {verdict:15} "
            f"dims={','.join(row['dimensions']) or '-'} "
            f"lines={row['position_lines_ok']}/{row['position_lines_total']} "
            f"firstlineno={'=' if row['firstlineno_equal'] else '!'}",
            file=sys.stderr,
        )
    for name, reason in tier.EXCLUDED_ATTRS:
        print(f"  excluded {name}: {reason}", file=sys.stderr)


if __name__ == "__main__":
    main()
