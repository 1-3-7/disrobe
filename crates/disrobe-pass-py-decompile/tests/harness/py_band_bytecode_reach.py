"""Report which opcodes a band's pinned-module population actually reaches.

A band gate pins a numerator, a denominator and a module count, but none of those say whether
the population it walked contains the bytecode that band introduced. Two bands can publish
different fractions of the same common subset and nothing notices. This script compiles the same
pinned module list the recompile-equivalence harness measures, with the running interpreter, and
reports the set of opcode names those code objects carry plus the count of code objects that
declare positional-only parameters.

The reference is CPython's own compiler and `dis` module. Nothing here reads disrobe output.

Usage:
    python py_band_bytecode_reach.py --lib DIR --modules FILE

  --lib      the interpreter's stdlib Lib directory (where the pinned module paths resolve).
  --modules  newline-delimited file of module paths relative to --lib; blank lines and lines
             starting with '#' are ignored.

Emits a single JSON object on stdout. Runtime-compatible with CPython 3.8 and later, because the
band interpreter is the one that runs it.
"""

from __future__ import annotations

import argparse
import dis
import json
import os
import platform
import sys
import types

MAX_CODE_OBJECTS = 400000


def read_pinned(modules_file, lib):
    paths = []
    with open(modules_file, encoding="utf-8") as handle:
        for line in handle:
            rel = line.strip()
            if not rel or rel.startswith("#"):
                continue
            paths.append(os.path.join(lib, rel.replace("/", os.sep)))
    return paths


def nested_code_objects(module_code):
    reached = []
    stack = [module_code]
    while stack:
        if len(reached) >= MAX_CODE_OBJECTS:
            raise RuntimeError(
                "the pinned population exceeded the %d code-object ceiling this script walks; "
                "raise the ceiling deliberately rather than reporting a truncated reach"
                % MAX_CODE_OBJECTS
            )
        current = stack.pop()
        reached.append(current)
        for konst in current.co_consts:
            if isinstance(konst, types.CodeType) and konst.co_name != "__annotate__":
                stack.append(konst)
    return reached


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", required=True)
    parser.add_argument("--modules", required=True)
    args = parser.parse_args()

    if not os.path.isdir(args.lib):
        sys.stderr.write("--lib %s is not a directory\n" % args.lib)
        return 2

    listed = read_pinned(args.modules, args.lib)
    if not listed:
        sys.stderr.write("--modules %s lists no module paths\n" % args.modules)
        return 2

    present = [path for path in listed if os.path.isfile(path)]
    if not present:
        sys.stderr.write(
            "none of the %d pinned module paths resolve under %s, so the reported reach would be "
            "an empty set rather than a measurement\n" % (len(listed), args.lib)
        )
        return 2

    opnames = set()
    posonly_objects = 0
    code_objects = 0
    modules = 0
    unreadable = []

    for path in present:
        try:
            with open(path, encoding="utf-8", errors="replace") as source:
                module_code = compile(source.read(), path, "exec", dont_inherit=True)
        except (SyntaxError, ValueError) as failure:
            unreadable.append("%s: %s" % (os.path.relpath(path, args.lib), failure))
            continue
        modules += 1
        for code in nested_code_objects(module_code):
            code_objects += 1
            if getattr(code, "co_posonlyargcount", 0) > 0:
                posonly_objects += 1
            for instruction in dis.get_instructions(code):
                opnames.add(instruction.opname)

    json.dump(
        {
            "cpython_version": platform.python_version(),
            "pinned": len(listed),
            "missing_from_lib": len(listed) - len(present),
            "modules": modules,
            "code_objects": code_objects,
            "posonly_objects": posonly_objects,
            "opnames": sorted(opnames),
        },
        sys.stdout,
    )
    sys.stdout.write("\n")

    for note in unreadable:
        sys.stderr.write("uncompilable: %s\n" % note)
    return 0


if __name__ == "__main__":
    sys.exit(main())
