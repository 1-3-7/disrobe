"""Arbitrary real-world Python decompile measurement (CPython 3.14 stdlib, pinned corpus).

Per-code-object recompile-to-equivalent-bytecode oracle. For each pinned stdlib module:
compile it with the running interpreter -> write a .pyc -> run `disrobe py decompile` on that
.pyc -> recompile disrobe's recovered source with the same interpreter -> compare EVERY nested
code object (module / function / method / class body / comprehension / lambda) individually via
an opcode-normalized diff. The oracle is non-circular: disrobe's output is graded against a real
CPython recompile, never against disrobe's own re-emission.

Reports the per-code-object percentage (the granular, monotonic metric that guides fixes) and the
whole-module exact percentage (the end goal), plus a failure taxonomy. No installs and no stdlib
vendoring: the caller passes an explicit, version-stable list of module paths (relative to the
interpreter's Lib directory) so the same modules are measured on every machine.

Usage:
    python py_arbitrary_measure.py --disrobe PATH --lib DIR --modules FILE

  --disrobe  path to the built `disrobe` binary.
  --lib      CPython 3.14 stdlib Lib directory (where the pinned module paths resolve).
  --modules  newline-delimited file of module paths relative to --lib (the pinned corpus);
             blank lines and lines starting with '#' are ignored.

Emits a single JSON object on the first line of stdout, then a human-readable taxonomy on stderr.

Pass --strict-tier to additionally measure, on top of the normalized recompile-equivalence
oracle above, byte-identical faithfulness (co_code plus every co_* structural field, compared
recursively through nested code objects in co_consts) and co_positions() fidelity (line-level and
full lineno/col granularity). The strict tier runs only on code objects that already pass the
normalized oracle above; it is a pure measurement and asserts nothing on its own.
"""

from __future__ import annotations

import argparse
import difflib
import dis
import glob
import importlib.util
import json
import marshal
import math
import os
import platform
import subprocess
import sys
import tempfile
import types
import warnings

NOOP = {
    "NOP",
    "CACHE",
    "RESUME",
    "COPY_FREE_VARS",
    "MAKE_CELL",
    "NOT_TAKEN",
    "PRECALL",
    "RETURN_GENERATOR",
    "EXTENDED_ARG",
}
SPLIT2 = {
    "LOAD_FAST_LOAD_FAST": ("LOAD_FAST", "LOAD_FAST"),
    "LOAD_FAST_BORROW_LOAD_FAST_BORROW": ("LOAD_FAST", "LOAD_FAST"),
    "STORE_FAST_LOAD_FAST": ("STORE_FAST", "LOAD_FAST"),
    "STORE_FAST_STORE_FAST": ("STORE_FAST", "STORE_FAST"),
}
RENAME = {
    "LOAD_FAST_BORROW": "LOAD_FAST",
    "LOAD_FAST_CHECK": "LOAD_FAST",
    "LOAD_SMALL_INT": "LOAD_CONST",
}
JUMPS = {
    "JUMP_FORWARD": "JUMP",
    "JUMP_BACKWARD": "JUMP",
    "JUMP_BACKWARD_NO_INTERRUPT": "JUMP",
    "JUMP_NO_INTERRUPT": "JUMP",
    "JUMP_ABSOLUTE": "JUMP",
    "JUMP": "JUMP",
    "POP_JUMP_FORWARD_IF_TRUE": "JUMP_IF_TRUE",
    "POP_JUMP_BACKWARD_IF_TRUE": "JUMP_IF_TRUE",
    "POP_JUMP_IF_TRUE": "JUMP_IF_TRUE",
    "JUMP_IF_TRUE_OR_POP": "JUMP_IF_TRUE",
    "POP_JUMP_FORWARD_IF_FALSE": "JUMP_IF_FALSE",
    "POP_JUMP_BACKWARD_IF_FALSE": "JUMP_IF_FALSE",
    "POP_JUMP_IF_FALSE": "JUMP_IF_FALSE",
    "JUMP_IF_FALSE_OR_POP": "JUMP_IF_FALSE",
    "POP_JUMP_FORWARD_IF_NONE": "JUMP_IF_NONE",
    "POP_JUMP_IF_NONE": "JUMP_IF_NONE",
    "POP_JUMP_FORWARD_IF_NOT_NONE": "JUMP_IF_NOT_NONE",
    "POP_JUMP_IF_NOT_NONE": "JUMP_IF_NOT_NONE",
}
ARGREPR_OPS = frozenset(
    {
        "LOAD_FAST",
        "STORE_FAST",
        "DELETE_FAST",
        "LOAD_GLOBAL",
        "STORE_GLOBAL",
        "LOAD_NAME",
        "STORE_NAME",
        "LOAD_ATTR",
        "STORE_ATTR",
        "LOAD_METHOD",
        "LOAD_DEREF",
        "STORE_DEREF",
        "IMPORT_NAME",
        "IMPORT_FROM",
        "COMPARE_OP",
        "CONTAINS_OP",
        "IS_OP",
        "BINARY_OP",
        "CALL",
        "CALL_KW",
    }
)


def norm_instrs(code):
    out = []
    for ins in dis.get_instructions(code):
        op = ins.opname
        if op in NOOP:
            continue
        if op in SPLIT2:
            a, b = ins.argval if isinstance(ins.argval, tuple) else (None, None)
            out.append((SPLIT2[op][0], a))
            out.append((SPLIT2[op][1], b))
            continue
        op = RENAME.get(op, op)
        if op in JUMPS:
            out.append((JUMPS[op], None))
        elif op == "LOAD_CONST":
            v = ins.argval
            if isinstance(v, types.CodeType):
                out.append(("LOAD_CONST", "<code>"))
            elif isinstance(v, (frozenset, set)):
                kind = "frozenset" if isinstance(v, frozenset) else "set"
                out.append(("LOAD_CONST", (kind, frozenset(repr(e) for e in v))))
            else:
                out.append(("LOAD_CONST", repr(v)))
        elif op == "STORE_NAME" and ins.argrepr in ("__firstlineno__", "__static_attributes__"):
            if out and out[-1][0] == "LOAD_CONST":
                out.pop()
        elif op in ARGREPR_OPS:
            out.append((op, ins.argrepr))
        else:
            out.append((op, None))
    return out


def walk(code, qual="<module>"):
    yield qual, code
    for c in code.co_consts:
        if isinstance(c, types.CodeType):
            if c.co_name == "__annotate__":
                continue
            yield from walk(c, f"{qual}.{c.co_name}")


def own_equiv(a, b):
    if norm_instrs(a) != norm_instrs(b):
        return False, "code"
    for attr in ("co_argcount", "co_posonlyargcount", "co_kwonlyargcount"):
        if getattr(a, attr) != getattr(b, attr):
            return False, "sig"
    return True, ""


Position = tuple[int | None, int | None, int | None, int | None]
MAX_ALIGN_INSTRS = 6000


def consts_equal(a: object, b: object) -> bool:
    if type(a) is not type(b):
        return False
    if isinstance(a, types.CodeType) and isinstance(b, types.CodeType):
        return byte_identical(a, b)
    if isinstance(a, tuple) and isinstance(b, tuple):
        return len(a) == len(b) and all(consts_equal(x, y) for x, y in zip(a, b, strict=True))
    if isinstance(a, (frozenset, set)) and isinstance(b, (frozenset, set)):
        return a == b
    if isinstance(a, float) and isinstance(b, float):
        if math.isnan(a) and math.isnan(b):
            return True
        return a == b and math.copysign(1.0, a) == math.copysign(1.0, b)
    if isinstance(a, complex) and isinstance(b, complex):
        return consts_equal(a.real, b.real) and consts_equal(a.imag, b.imag)
    return a == b


def byte_identical(a: types.CodeType, b: types.CodeType) -> bool:
    if a.co_code != b.co_code:
        return False
    for attr in (
        "co_names",
        "co_varnames",
        "co_freevars",
        "co_cellvars",
        "co_flags",
        "co_stacksize",
        "co_exceptiontable",
    ):
        if getattr(a, attr) != getattr(b, attr):
            return False
    if len(a.co_consts) != len(b.co_consts):
        return False
    return all(consts_equal(x, y) for x, y in zip(a.co_consts, b.co_consts, strict=True))


def classify(ins: dis.Instruction) -> tuple[str, object]:
    op = RENAME.get(ins.opname, ins.opname)
    if op in JUMPS:
        return (JUMPS[op], None)
    if op == "LOAD_CONST":
        v = ins.argval
        if isinstance(v, types.CodeType):
            return ("LOAD_CONST", "<code>")
        if isinstance(v, (frozenset, set)):
            kind = "frozenset" if isinstance(v, frozenset) else "set"
            return ("LOAD_CONST", (kind, frozenset(repr(e) for e in v)))
        return ("LOAD_CONST", (type(v).__name__, repr(v)))
    if op in SPLIT2:
        return (op, ins.argval)
    if op in ARGREPR_OPS:
        return (op, ins.argrepr)
    return (op, None)


def instr_seq(code: types.CodeType) -> list[tuple[tuple[str, object], Position]]:
    positions: list[Position] = list(code.co_positions())
    out: list[tuple[tuple[str, object], Position]] = []
    for ins in dis.get_instructions(code):
        if ins.opname in NOOP:
            continue
        idx = ins.offset // 2
        pos: Position = positions[idx] if idx < len(positions) else (None, None, None, None)
        out.append((classify(ins), pos))
    return out


def is_no_debug_ranges(code: types.CodeType) -> bool:
    positions: list[Position] = list(code.co_positions())
    if not positions:
        return False
    return all(p[2] is None and p[3] is None for p in positions)


def align_positions(
    a: types.CodeType, b: types.CodeType
) -> tuple[list[tuple[Position, Position]], int, int]:
    if a.co_code == b.co_code:
        pos_a: list[Position] = list(a.co_positions())
        pos_b: list[Position] = list(b.co_positions())
        pairs: list[tuple[Position, Position]] = list(zip(pos_a, pos_b, strict=True))
        return pairs, len(pairs), len(pairs)
    seq_a = instr_seq(a)
    seq_b = instr_seq(b)
    total = max(len(seq_a), len(seq_b))
    if len(seq_a) > MAX_ALIGN_INSTRS or len(seq_b) > MAX_ALIGN_INSTRS:
        return [], 0, total
    keys_a = [k for k, _ in seq_a]
    keys_b = [k for k, _ in seq_b]
    matcher = difflib.SequenceMatcher(None, keys_a, keys_b, autojunk=False)
    aligned: list[tuple[Position, Position]] = []
    for block in matcher.get_matching_blocks():
        for i in range(block.size):
            aligned.append((seq_a[block.a + i][1], seq_b[block.b + i][1]))
    return aligned, len(aligned), total


def group(code):
    g = {}
    for q, c in walk(code):
        g.setdefault(q, []).append(c)
    return g


def decompile(disrobe, pyc, outdir):
    r = subprocess.run(
        [disrobe, "py", "decompile", pyc, "--out", outdir],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if r.returncode != 0:
        return None
    cands = glob.glob(os.path.join(outdir, "**", "*.py"), recursive=True)
    return max(cands, key=os.path.getsize) if cands else None


def read_pinned(modules_file, lib):
    paths = []
    with open(modules_file, encoding="utf-8") as fh:
        for line in fh:
            rel = line.strip()
            if not rel or rel.startswith("#"):
                continue
            paths.append(os.path.join(lib, rel.replace("/", os.sep)))
    return paths


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--disrobe", required=True)
    ap.add_argument("--lib", required=True)
    ap.add_argument("--modules", required=True)
    ap.add_argument("--strict-tier", action="store_true")
    ap.add_argument("--object-ledger", default=None)
    args = ap.parse_args()

    ledger: list[str] = []

    def record(module_path: str, qualname: str, position: int, verdict: str) -> None:
        if args.object_ledger is None:
            return
        rel = os.path.relpath(module_path, args.lib).replace(os.sep, "/")
        ledger.append(f"{rel}\t{qualname}\t{position}\t{verdict}")

    warnings.simplefilter("ignore")
    files = read_pinned(args.modules, args.lib)

    pinned = len(files)
    missing_from_lib = [f for f in files if not os.path.isfile(f)]
    files = [f for f in files if os.path.isfile(f)]

    tot_obj = ok_obj = 0
    tot_mod = ok_mod = 0
    reasons = {}
    samples = {}
    sibling_collisions = 0

    strict_recompile_equivalent = 0
    strict_byte_identical = 0
    strict_lines_ok = 0
    strict_lines_total = 0
    strict_full_ok = 0
    strict_full_total = 0
    strict_align_aligned = 0
    strict_align_total = 0
    strict_no_debug_ranges_objects = 0

    for f in files:
        try:
            a = compile(
                open(f, encoding="utf-8", errors="replace").read(),
                f,
                "exec",
                dont_inherit=True,
                optimize=sys.flags.optimize,
            )
        except Exception:
            reasons["COMPILE_ERR"] = reasons.get("COMPILE_ERR", 0) + 1
            continue
        ga = group(a)
        nobj = sum(len(v) for v in ga.values())
        tot_obj += nobj
        tot_mod += 1
        with tempfile.TemporaryDirectory() as td:
            pyc = os.path.join(td, "m.pyc")
            with open(pyc, "wb") as w:
                w.write(importlib.util.MAGIC_NUMBER)
                w.write(b"\x00" * 12)
                marshal.dump(a, w)
            rec = decompile(args.disrobe, pyc, os.path.join(td, "out"))
            mod_ok = 0
            if rec is None:
                reasons["DECOMPILE_ERR"] = reasons.get("DECOMPILE_ERR", 0) + nobj
                for q, alist in ga.items():
                    for i in range(len(alist)):
                        record(f, q, i, "DECOMPILE_ERR")
            else:
                try:
                    b = compile(
                        open(rec, encoding="utf-8", errors="replace").read(),
                        rec,
                        "exec",
                        dont_inherit=True,
                        optimize=sys.flags.optimize,
                    )
                    gb = group(b)
                    for q, alist in ga.items():
                        blist = gb.get(q, [])
                        # Sibling-masking guard (honesty mandate): code objects that share a
                        # qualified name (multiple <lambda>/<listcomp>/<genexpr> under one parent,
                        # overloaded nested defs) are paired only by list position. A positional
                        # pairing can silently grade original-A against recompiled-B and let a real
                        # miss pass on its sibling. When the recovered group has a different count
                        # than the original, that pairing is unsound, so every object in the group
                        # is charged as a failure (MISSING for the shortfall, COLLISION for the
                        # rest) rather than positionally matched. A mismatch in one code object can
                        # never silently pass its siblings.
                        if len(blist) != len(alist):
                            if len(alist) > 1:
                                sibling_collisions += 1
                            for i in range(len(alist)):
                                if i >= len(blist):
                                    reasons["MISSING"] = reasons.get("MISSING", 0) + 1
                                    record(f, q, i, "MISSING")
                                else:
                                    reasons["COLLISION"] = reasons.get("COLLISION", 0) + 1
                                    record(f, q, i, "COLLISION")
                                    samples.setdefault("COLLISION", [])
                                    if len(samples["COLLISION"]) < 12:
                                        samples["COLLISION"].append(
                                            f"{os.path.basename(f)}:{q} "
                                            f"({len(alist)} orig vs {len(blist)} rec)"
                                        )
                            continue
                        for position, (ac, bc) in enumerate(zip(alist, blist)):
                            eq, why = own_equiv(ac, bc)
                            record(f, q, position, "OK" if eq else why)
                            if eq:
                                ok_obj += 1
                                mod_ok += 1
                                if args.strict_tier:
                                    strict_recompile_equivalent += 1
                                    if byte_identical(ac, bc):
                                        strict_byte_identical += 1
                                    pairs, aligned, tot_align = align_positions(ac, bc)
                                    strict_align_aligned += aligned
                                    strict_align_total += tot_align
                                    strict_lines_total += len(pairs)
                                    strict_lines_ok += sum(
                                        1 for pa, pb in pairs if pa[0] == pb[0] and pa[1] == pb[1]
                                    )
                                    if is_no_debug_ranges(ac):
                                        strict_no_debug_ranges_objects += 1
                                    else:
                                        strict_full_total += len(pairs)
                                        strict_full_ok += sum(1 for pa, pb in pairs if pa == pb)
                            else:
                                reasons[why] = reasons.get(why, 0) + 1
                                samples.setdefault(why, [])
                                if len(samples[why]) < 12:
                                    samples[why].append(f"{os.path.basename(f)}:{q}")
                except SyntaxError as e:
                    reasons["SYNTAX_ERR"] = reasons.get("SYNTAX_ERR", 0) + nobj
                    for q, alist in ga.items():
                        for i in range(len(alist)):
                            record(f, q, i, "SYNTAX_ERR")
                    samples.setdefault("SYNTAX_ERR", [])
                    if len(samples["SYNTAX_ERR"]) < 12:
                        samples["SYNTAX_ERR"].append(
                            f"{os.path.basename(f)}: {e.msg}@L{e.lineno}"
                        )
            if mod_ok == nobj:
                ok_mod += 1

    result = {
        "lib": args.lib,
        "pinned": pinned,
        "missing_from_lib": len(missing_from_lib),
        "modules": tot_mod,
        "modules_exact": ok_mod,
        "module_pct": round(100.0 * ok_mod / tot_mod, 2) if tot_mod else 0,
        "code_objects": tot_obj,
        "objects_ok": ok_obj,
        "object_pct": round(100.0 * ok_obj / tot_obj, 2) if tot_obj else 0,
        "sibling_collisions": sibling_collisions,
        "cpython_version": platform.python_version(),
        "magic_number": importlib.util.MAGIC_NUMBER.hex(),
    }
    if args.strict_tier:
        strict_byte_identical_pct = (
            round(100.0 * strict_byte_identical / strict_recompile_equivalent, 2)
            if strict_recompile_equivalent
            else 0
        )
        strict_lines_pct = (
            round(100.0 * strict_lines_ok / strict_lines_total, 2) if strict_lines_total else 0
        )
        strict_full_pct = (
            round(100.0 * strict_full_ok / strict_full_total, 2) if strict_full_total else 0
        )
        strict_alignment_coverage_pct = (
            round(100.0 * strict_align_aligned / strict_align_total, 2)
            if strict_align_total
            else 0
        )
        result.update(
            {
                "strict_recompile_equivalent": strict_recompile_equivalent,
                "strict_byte_identical": strict_byte_identical,
                "strict_byte_identical_pct": strict_byte_identical_pct,
                "strict_position_lines_ok": strict_lines_ok,
                "strict_position_lines_total": strict_lines_total,
                "strict_position_lines_pct": strict_lines_pct,
                "strict_position_full_ok": strict_full_ok,
                "strict_position_full_total": strict_full_total,
                "strict_position_full_pct": strict_full_pct,
                "strict_alignment_coverage_pct": strict_alignment_coverage_pct,
                "strict_no_debug_ranges_objects": strict_no_debug_ranges_objects,
            }
        )
        print(json.dumps(result))
        print(
            f"\n{strict_recompile_equivalent} recompile-equivalent; of those, "
            f"{strict_byte_identical} byte-identical ({strict_byte_identical_pct}%); "
            f"positions: lines {strict_lines_pct}%, full {strict_full_pct}% "
            f"(alignment coverage {strict_alignment_coverage_pct}%, "
            f"{strict_no_debug_ranges_objects} objects scored lines-only, no debug ranges)",
            file=sys.stderr,
        )
    else:
        print(json.dumps(result))

    if args.object_ledger is not None:
        ledger.sort()
        with open(args.object_ledger, "w", encoding="utf-8", newline="\n") as ledger_file:
            ledger_file.write("\n".join(ledger))
            ledger_file.write("\n")

    print("\n=== failure reasons (by code-object count) ===", file=sys.stderr)
    for why, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
        print(f"  {n:5}  {why}", file=sys.stderr)
    if missing_from_lib:
        print(
            f"\n{len(missing_from_lib)} pinned modules absent from this Lib "
            f"(stdlib drift across 3.14.x); first few:",
            file=sys.stderr,
        )
        for m in missing_from_lib[:8]:
            print(f"  {os.path.relpath(m, args.lib)}", file=sys.stderr)
    for why in sorted(reasons, key=lambda w: -reasons[w])[:5]:
        if samples.get(why):
            print(f"\n--- {why} sample ---", file=sys.stderr)
            for s in samples[why]:
                print(f"  {s}", file=sys.stderr)


if __name__ == "__main__":
    main()
