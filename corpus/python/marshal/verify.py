import re
import subprocess
import sys
import tempfile
from pathlib import Path

CORPUS = Path(__file__).resolve().parent
ROOT = CORPUS.parents[2]
ORIGINALS = CORPUS / "originals"
VARIANTS = CORPUS / "variants"

TAG_TO_LAUNCHER = {
    "py39": ["py", "-3.9"],
    "py311": ["py", "-V:Astral/CPython3.11.15"],
    "py312": ["py", "-3.12"],
    "py314": ["py", "-3.14"],
    "py315": ["py", "-V:Astral/CPython3.15.0b1"],
}
TAG_TO_MINOR = {
    "py39": "3.9",
    "py311": "3.11",
    "py312": "3.12",
    "py314": "3.14",
    "py315": "3.15",
}

ADDR = re.compile(r"0x[0-9A-Fa-f]+")
CODEOBJ = re.compile(r"<code object [^>]+>")
INSTR = re.compile(r"^(?:\s*\d+)?\s*(?:>>)?\s*\d+\s+([A-Z][A-Z0-9_]+.*)$")


def normalize_dis(text):
    out = []
    for raw in text.splitlines():
        line = ADDR.sub("0xADDR", raw)
        line = re.sub(r", line \d+", "", line)
        line = re.sub(r"<code object .*>", "<code object>", line)
        line = re.sub(r"file \"[^\"]+\"", 'file "<f>"', line)
        m = INSTR.match(line)
        if m:
            out.append(m.group(1).rstrip())
        elif line.strip().startswith("Disassembly of"):
            out.append("Disassembly of <code object>")
    return "\n".join(out)


def dis_of_source(launcher, source):
    prog = (
        "import sys,dis,io\n"
        "src=sys.stdin.read()\n"
        "code=compile(src,'<m>','exec')\n"
        "buf=io.StringIO()\n"
        "dis.dis(code,file=buf)\n"
        "sys.stdout.write(buf.getvalue())\n"
    )
    res = subprocess.run(
        launcher + ["-c", prog],
        input=source,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        return None
    return normalize_dis(res.stdout)


def disrobe_recover(disrobe, fixture, minor):
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "recovered.py"
        cmd = [
            str(disrobe),
            "py",
            "deob",
            str(fixture),
            "--out",
            str(out),
            "--pyver",
            minor,
            "--force",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            return None, res.stdout + res.stderr
        if not out.exists():
            return None, "no output written"
        return out.read_text(encoding="utf-8", errors="replace"), res.stdout


def main():
    disrobe = ROOT / "target" / "release" / ("disrobe.exe" if sys.platform == "win32" else "disrobe")
    if not disrobe.exists():
        print("disrobe release binary not found at", disrobe)
        return 2

    wrappers = [
        "exec_plain",
        "exec_zlib",
        "exec_b64",
        "exec_b64_zlib",
        "exec_import_dunder",
        "exec_hex",
    ]
    passed = 0
    failed = 0
    skipped = 0
    failures = []

    for src_path in sorted(ORIGINALS.glob("*.py")):
        name = src_path.stem
        original_src = src_path.read_text(encoding="utf-8")
        for tag, launcher in TAG_TO_LAUNCHER.items():
            minor = TAG_TO_MINOR[tag]
            orig_dis = dis_of_source(launcher, original_src)
            if orig_dis is None:
                skipped += 1
                continue
            targets = [f"{name}.{tag}.{w}.py" for w in wrappers]
            targets.append(f"{name}.{tag}.bare.marshal")
            for fname in targets:
                fixture = VARIANTS / fname
                if not fixture.exists():
                    skipped += 1
                    continue
                recovered, log = disrobe_recover(disrobe, fixture, minor)
                if recovered is None:
                    failed += 1
                    failures.append((fname, "recover failed: " + (log or "")[:200]))
                    continue
                rec_dis = dis_of_source(launcher, recovered)
                if rec_dis is None:
                    failed += 1
                    failures.append((fname, "recovered source did not recompile"))
                    continue
                if rec_dis == orig_dis:
                    passed += 1
                else:
                    failed += 1
                    failures.append((fname, "dis mismatch"))

    print(f"recompile-equivalence: {passed} passed, {failed} failed, {skipped} skipped")
    for fname, why in failures[:40]:
        print(f"  FAIL {fname}: {why}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
