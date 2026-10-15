"""Rebuild the Hermes behaviour fixtures from their authored sources.

Usage: python build.py <directory holding hermesc and hermes from hermes-engine-cli 0.12.0>

Every command runs with this directory as its working directory and names its input by a
relative path, so the debug information inside each .hbc records only "<name>.js".
Each program is compiled by hermesc (HBC v89) and run by the Hermes interpreter of the
same release; the interpreter's standard output is the reference the decompiled program
must reproduce.
"""

import hashlib
import os
import subprocess
import sys

PROGRAMS = [
    "mixed",
    "control",
    "closures",
    "objects",
    "exceptions",
    "generators",
    "async",
    "values",
    "metro",
    "construct",
    "cleanup",
    "delegation",
    "names",
    "rnassets",
    "branches",
]


def sha256(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def main() -> int:
    tools = sys.argv[1]
    here = os.path.dirname(os.path.abspath(__file__))
    suffix = ".exe" if os.name == "nt" else ""
    hermesc = os.path.join(tools, "hermesc" + suffix)
    hermes = os.path.join(tools, "hermes" + suffix)
    for name in PROGRAMS:
        source = name + ".js"
        bytecode = name + ".hbc"
        subprocess.run(
            [hermesc, "-emit-binary", "-out", bytecode, source],
            cwd=here,
            check=True,
        )
        run = subprocess.run(
            [hermes, "-b", bytecode],
            cwd=here,
            check=True,
            capture_output=True,
        )
        stdout = run.stdout.replace(b"\r\n", b"\n")
        reference = name + ".hermes-stdout.txt"
        with open(os.path.join(here, reference), "wb") as handle:
            handle.write(stdout)
        for item in (source, bytecode, reference):
            print(item, os.path.getsize(os.path.join(here, item)), sha256(os.path.join(here, item)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
