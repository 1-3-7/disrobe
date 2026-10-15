"""Rebuild the HBC v85, v90 and v94 fixtures from the authored sources.

Usage: python build.py <hermesc v85> <hermesc v90> <hermesc v94>

The three compilers are the win64 hermesc builds the react-native npm package ships in
sdks/hermesc/win64-bin: react-native 0.69.12 (HBC v85), 0.71.19 (HBC v90) and 0.72.17
(HBC v94), the bytecode versions React Native 0.69 to 0.72 apps carry. Each source
(../sample/sample.js and every ../behaviour/<name>.js) is copied into a scratch directory and
compiled there under its bare name, so the debug information inside each .hbc records only
"<name>.js". Each compiler then disassembles the bytecode it wrote with -dump-bytecode; it
recognises bytecode input by the .hbc extension, so the scratch copy is named
<name>.v<version>.hbc. The dump up to its debug tables is the reference the disassembler is
graded against. The sample goes to ../sample/sample.hbc.v<version> with its dump in
../sample/upstream-disasm/hbc<version>.txt, beside the other releases' samples; the behaviour
programs stay here as <name>.hbc.v<version> and <name>.v<version>.hermesc-dump.txt. The v85
compiler rejects BigInt literals, so objects.js and values.js are not compiled at v85. No
bytecode is executed.
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
]
VERSIONS = [85, 90, 94]
UNSUPPORTED = {85: {"objects", "values"}}


def sha256(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def compiler_version(hermesc: str) -> int:
    text = subprocess.run([hermesc, "-version"], check=True, capture_output=True, text=True).stdout
    for line in text.splitlines():
        if "HBC bytecode version:" in line:
            return int(line.rsplit(":", 1)[1])
    raise SystemExit(f"{hermesc} does not report its bytecode version")


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    compilers = list(zip(VERSIONS, sys.argv[1:4]))
    for version, hermesc in compilers:
        if compiler_version(hermesc) != version:
            raise SystemExit(f"{hermesc} is not the HBC v{version} compiler")
    with tempfile.TemporaryDirectory() as scratch:
        for relative in PROGRAMS:
            source = os.path.normpath(os.path.join(here, relative))
            name = os.path.splitext(os.path.basename(source))[0]
            shutil.copyfile(source, os.path.join(scratch, name + ".js"))
            for version, hermesc in compilers:
                if name in UNSUPPORTED.get(version, set()):
                    continue
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
                if name == "sample":
                    committed = os.path.join(here, "..", "sample", f"sample.hbc.v{version}")
                    reference = os.path.join(here, "..", "sample", "upstream-disasm", f"hbc{version}.txt")
                else:
                    committed = os.path.join(here, f"{name}.hbc.v{version}")
                    reference = os.path.join(here, f"{name}.v{version}.hermesc-dump.txt")
                with open(reference, "wb") as handle:
                    handle.write(b"\n".join(kept).rstrip(b"\n") + b"\n")
                shutil.copyfile(os.path.join(scratch, bytecode), committed)
                for path in (committed, reference):
                    print(os.path.relpath(path, here).replace(os.sep, "/"), os.path.getsize(path), sha256(path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
