from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE: Path = Path(__file__).resolve().parent
SRC: Path = HERE / "corpus.c"
OUT: Path = HERE.parent.parent / "aarch64_recovery_corpus.inc"
LEVELS: tuple[str, ...] = ("O0", "O1", "O2", "O3", "Os")
FUNC_RE: re.Pattern[str] = re.compile(r"^[0-9a-f]+ <([A-Za-z_][A-Za-z0-9_]*)>:\s*$")
INSN_RE: re.Pattern[str] = re.compile(r"^\s*[0-9a-f]+:\s+([0-9a-f]{8})\s")


def disassemble(level: str, out_dir: Path, /) -> dict[str, list[int]]:
    obj: Path = out_dir / f"corpus_{level}.o"
    compile_cmd: list[str] = [
        "clang",
        "--target=aarch64-linux-gnu",
        f"-{level}",
        "-fno-builtin",
        "-fomit-frame-pointer",
        "-c",
        str(SRC),
        "-o",
        str(obj),
    ]
    subprocess.run(compile_cmd, check=True, capture_output=True)
    dumped: subprocess.CompletedProcess[str] = subprocess.run(
        ["llvm-objdump", "-d", str(obj)],
        check=True,
        capture_output=True,
        text=True,
    )
    out: dict[str, list[int]] = {}
    current: str | None = None
    for line in dumped.stdout.splitlines():
        matched_func: re.Match[str] | None = FUNC_RE.match(line)
        if matched_func is not None:
            name: str = matched_func.group(1)
            current = name
            out[name] = []
            continue
        if current is None:
            continue
        matched_insn: re.Match[str] | None = INSN_RE.match(line)
        if matched_insn is None:
            continue
        word: int = int(matched_insn.group(1), 16)
        out[current].extend(word.to_bytes(4, "little"))
    return {name: body for name, body in out.items() if body}


def main() -> int:
    rows: list[str] = []
    per_level: dict[str, int] = {}
    with tempfile.TemporaryDirectory() as tmp:
        out_dir: Path = Path(tmp)
        for level in LEVELS:
            functions: dict[str, list[int]] = disassemble(level, out_dir)
            per_level[level] = len(functions)
            for name in sorted(functions):
                body: list[int] = functions[name]
                joined: str = ", ".join(f"0x{value:02x}" for value in body)
                rows.append(f'    ("{level}", "{name}", &[{joined}]),')
    OUT.write_text("[\n" + "\n".join(rows) + "\n]\n", encoding="utf-8")
    total: int = sum(per_level.values())
    print(f"levels={per_level} total_cases={total}")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
