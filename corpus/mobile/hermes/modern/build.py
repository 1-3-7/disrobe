"""Rebuild the HBC v98 and v99 fixtures from the authored sources.

Usage: python build.py <hermesc from npm hermes-compiler 250829098.0.19> <hermesc from npm hermes-compiler 260318099.0.4>

Each source (../sample/sample.js and every ../behaviour/<name>.js) is copied into a scratch
directory and compiled there under its bare name, so the debug information inside each .hbc
records only "<name>.js". Each compiler then disassembles the bytecode it wrote with
-dump-bytecode. It recognises bytecode input by the .hbc extension, so the scratch copy is named
<name>.v<version>.hbc and the committed copy <name>.hbc.v<version>. The dump up to its debug
tables is the reference the disassembler is graded against. No bytecode is executed.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

PROGRAMS = [
    "../sample/sample.js",
    "../behaviour/mixed.js",
    "../behaviour/control.js",
    "../behaviour/closures.js",
    "../behaviour/objects.js",
    "../behaviour/exceptions.js",
    "../behaviour/generators.js",
    "../behaviour/async.js",
    "../behaviour/values.js",
    "../behaviour/metro.js",
    "../behaviour/construct.js",
    "../behaviour/cleanup.js",
    "../behaviour/delegation.js",
    "../behaviour/names.js",
    "../behaviour/rnassets.js",
    "../behaviour/branches.js",
    "features.js",
]


def sha256(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    compilers = [(98, sys.argv[1]), (99, sys.argv[2])]
    with tempfile.TemporaryDirectory() as scratch:
        for relative in PROGRAMS:
            source = os.path.normpath(os.path.join(here, relative))
            name = os.path.splitext(os.path.basename(source))[0]
            shutil.copyfile(source, os.path.join(scratch, name + ".js"))
            for version, hermesc in compilers:
                bytecode = f"{name}.v{version}.hbc"
                subprocess.run(
                    [hermesc, "-emit-binary", "-out", bytecode, name + ".js"],
                    cwd=scratch,
                    check=True,
                )
                dump = subprocess.run(
                    [hermesc, "-dump-bytecode", bytecode],
                    cwd=scratch,
                    check=True,
                    capture_output=True,
                ).stdout.replace(b"\r\n", b"\n")
                kept = []
                for line in dump.split(b"\n"):
                    if line.startswith(b"Debug "):
                        break
                    kept.append(line)
                reference = f"{name}.v{version}.hermesc-dump.txt"
                with open(os.path.join(here, reference), "wb") as handle:
                    handle.write(b"\n".join(kept).rstrip(b"\n") + b"\n")
                committed = f"{name}.hbc.v{version}"
                shutil.copyfile(os.path.join(scratch, bytecode), os.path.join(here, committed))
                for item in (committed, reference):
                    path = os.path.join(here, item)
                    print(item, os.path.getsize(path), sha256(path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
