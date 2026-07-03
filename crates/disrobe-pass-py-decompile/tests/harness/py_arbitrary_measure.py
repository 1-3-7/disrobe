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
"""

import argparse
import dis
import glob
import importlib.util
import json
import marshal
import os
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
        elif op in (
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
        ):
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
    args = ap.parse_args()

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

    for f in files:
        try:
            a = compile(open(f, encoding="utf-8", errors="replace").read(), f, "exec")
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
            else:
                try:
                    b = compile(open(rec, encoding="utf-8", errors="replace").read(), rec, "exec")
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
                                else:
                                    reasons["COLLISION"] = reasons.get("COLLISION", 0) + 1
                                    samples.setdefault("COLLISION", [])
                                    if len(samples["COLLISION"]) < 12:
                                        samples["COLLISION"].append(
                                            f"{os.path.basename(f)}:{q} "
                                            f"({len(alist)} orig vs {len(blist)} rec)"
                                        )
                            continue
                        for ac, bc in zip(alist, blist):
                            eq, why = own_equiv(ac, bc)
                            if eq:
                                ok_obj += 1
                                mod_ok += 1
                            else:
                                reasons[why] = reasons.get(why, 0) + 1
                                samples.setdefault(why, [])
                                if len(samples[why]) < 12:
                                    samples[why].append(f"{os.path.basename(f)}:{q}")
                except SyntaxError as e:
                    reasons["SYNTAX_ERR"] = reasons.get("SYNTAX_ERR", 0) + nobj
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
    }
    print(json.dumps(result))

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
