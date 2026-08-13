"""Failure-family clustering for the per-code-object recompile-equivalence measurement.

Runs the same pipeline as py_arbitrary_measure.py (compile a pinned stdlib module with the
running interpreter, decompile the .pyc with the real disrobe binary, recompile the recovered
source with the same interpreter, compare every nested code object) and, for every code object
that fails, derives a family key from the first normalized-instruction disagreement. The grading
functions are imported from py_arbitrary_measure.py rather than restated, so a band figure and a
family table can never be cut from two different oracles.

Usage:
    python py_failure_families.py --disrobe PATH --lib DIR --modules FILE [--top N]

Emits a single JSON object on the first line of stdout:

    {"failing_objects": N, "code_objects": N, "modules": N, "cpython_version": "...",
     "families": [{"family": "...", "objects": N, "modules": N, "samples": [...]}, ...]}

`failing_objects` is the denominator minus the numerator of the same band the measurement
harness reports, and the family counts sum to it exactly, so the table cannot describe a
population the band never measured.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import tempfile
import types
import warnings
from collections import Counter
from typing import Final

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import importlib.util
import marshal

from py_arbitrary_measure import decompile, group, norm_instrs, own_equiv, read_pinned

SAMPLES_PER_FAMILY: Final[int] = 6
END: Final[str] = "<end>"


def first_disagreement(a: types.CodeType, b: types.CodeType, /) -> tuple[str, str]:
    left: list[tuple[str, object]] = norm_instrs(a)
    right: list[tuple[str, object]] = norm_instrs(b)
    for index in range(max(len(left), len(right))):
        lop: str = left[index][0] if index < len(left) else END
        rop: str = right[index][0] if index < len(right) else END
        if index >= len(left) or index >= len(right) or left[index] != right[index]:
            if lop == rop:
                return (f"{lop}(arg)", f"{rop}(arg)")
            return (lop, rop)
    return (END, END)


class FamilyTable:
    def __init__(self: FamilyTable) -> None:
        self.objects: Counter[str] = Counter()
        self.modules: dict[str, set[str]] = {}
        self.samples: dict[str, list[str]] = {}

    def charge(self: FamilyTable, family: str, module: str, qualname: str, /) -> None:
        self.objects[family] += 1
        self.modules.setdefault(family, set()).add(module)
        bucket: list[str] = self.samples.setdefault(family, [])
        if len(bucket) < SAMPLES_PER_FAMILY:
            bucket.append(f"{module}:{qualname}")

    def total(self: FamilyTable, /) -> int:
        return int(sum(self.objects.values()))

    def rows(self: FamilyTable, top: int, /) -> list[dict[str, object]]:
        ordered: list[tuple[str, int]] = sorted(
            self.objects.items(), key=lambda kv: (-kv[1], kv[0])
        )
        if top > 0:
            ordered = ordered[:top]
        return [
            {
                "family": family,
                "objects": count,
                "modules": len(self.modules.get(family, set())),
                "samples": self.samples.get(family, []),
            }
            for family, count in ordered
        ]


def compile_module(path: str, /) -> types.CodeType | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text: str = handle.read()
        return compile(text, path, "exec", dont_inherit=True, optimize=sys.flags.optimize)
    except Exception:
        return None


def charge_whole_module(
    table: FamilyTable, grouped: dict[str, list[types.CodeType]], module: str, family: str, /
) -> None:
    for qualname, objects in grouped.items():
        for _ in objects:
            table.charge(family, module, qualname)


def measure_module(
    table: FamilyTable, disrobe: str, lib: str, path: str, /
) -> tuple[int, int, bool]:
    original: types.CodeType | None = compile_module(path)
    if original is None:
        return (0, 0, False)
    module: str = os.path.relpath(path, lib).replace(os.sep, "/")
    grouped: dict[str, list[types.CodeType]] = group(original)
    total: int = sum(len(v) for v in grouped.values())
    with tempfile.TemporaryDirectory() as scratch:
        pyc: str = os.path.join(scratch, "m.pyc")
        with open(pyc, "wb") as sink:
            sink.write(importlib.util.MAGIC_NUMBER)
            sink.write(b"\x00" * 12)
            marshal.dump(original, sink)
        recovered: str | None = decompile(disrobe, pyc, os.path.join(scratch, "out"))
        if recovered is None:
            charge_whole_module(table, grouped, module, "DECOMPILE_ERR")
            return (total, 0, True)
        try:
            with open(recovered, encoding="utf-8", errors="replace") as handle:
                text: str = handle.read()
            rebuilt: types.CodeType = compile(
                text, recovered, "exec", dont_inherit=True, optimize=sys.flags.optimize
            )
        except SyntaxError as broken:
            charge_whole_module(table, grouped, module, f"SYNTAX_ERR:{broken.msg}")
            return (total, 0, True)
        regrouped: dict[str, list[types.CodeType]] = group(rebuilt)
        ok: int = 0
        for qualname, objects in grouped.items():
            rebuilt_objects: list[types.CodeType] = regrouped.get(qualname, [])
            if len(rebuilt_objects) != len(objects):
                shortfall: str = "SIBLING_MISSING" if not rebuilt_objects else "SIBLING_COLLISION"
                for index in range(len(objects)):
                    verdict: str = (
                        "SIBLING_MISSING" if index >= len(rebuilt_objects) else shortfall
                    )
                    table.charge(verdict, module, qualname)
                continue
            for left, right in zip(objects, rebuilt_objects, strict=True):
                equivalent, why = own_equiv(left, right)
                if equivalent:
                    ok += 1
                    continue
                if why == "sig":
                    table.charge("SIG_ARGCOUNT", module, qualname)
                    continue
                lop, rop = first_disagreement(left, right)
                table.charge(f"CODE:{lop}->{rop}", module, qualname)
        return (total, ok, True)


def main() -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser()
    parser.add_argument("--disrobe", required=True)
    parser.add_argument("--lib", required=True)
    parser.add_argument("--modules", required=True)
    parser.add_argument("--top", type=int, default=0)
    args: argparse.Namespace = parser.parse_args()

    warnings.simplefilter("ignore")
    files: list[str] = [f for f in read_pinned(args.modules, args.lib) if os.path.isfile(f)]

    table: FamilyTable = FamilyTable()
    code_objects: int = 0
    objects_ok: int = 0
    modules: int = 0
    for path in files:
        total, ok, counted = measure_module(table, args.disrobe, args.lib, path)
        if not counted:
            continue
        modules += 1
        code_objects += total
        objects_ok += ok

    failing: int = code_objects - objects_ok
    charged: int = table.total()
    if charged != failing:
        raise SystemExit(
            f"family table charges {charged} objects but the same run measured {failing} "
            f"failing of {code_objects}; a family table that does not sum to the band's own "
            f"shortfall describes a population the band never measured"
        )

    result: dict[str, object] = {
        "cpython_version": platform.python_version(),
        "modules": modules,
        "code_objects": code_objects,
        "objects_ok": objects_ok,
        "failing_objects": failing,
        "families": table.rows(args.top),
    }
    print(json.dumps(result))
    print("\n=== failure families (by code-object count) ===", file=sys.stderr)
    for row in table.rows(args.top):
        print(f"  {row['objects']:5}  {row['family']}  ({row['modules']} modules)", file=sys.stderr)
        for sample in list(row["samples"]):
            print(f"           {sample}", file=sys.stderr)


if __name__ == "__main__":
    main()
