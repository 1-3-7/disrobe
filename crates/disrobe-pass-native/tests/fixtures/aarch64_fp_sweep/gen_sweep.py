from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE: Path = Path(__file__).resolve().parent
SRC: Path = HERE / "sweep.s"
OUT: Path = HERE.parent.parent / "aarch64_fp_sweep_corpus.inc"
ARCH_DIRECTIVE: str = ".arch armv8.5-a+fp16+jsconv"

FUNC_RE: re.Pattern[str] = re.compile(r"^[0-9a-f]+ <([A-Za-z_][A-Za-z0-9_]*)>:\s*$")
INSN_RE: re.Pattern[str] = re.compile(r"^\s*[0-9a-f]+:\s+([0-9a-f]{8})\s+(.*)$")


def assemble(out_dir: Path, /) -> tuple[dict[str, list[int]], dict[str, list[str]], str]:
    obj: Path = out_dir / "sweep.o"
    subprocess.run(
        [
            "clang",
            "--target=aarch64-linux-gnu",
            "-c",
            str(SRC),
            "-o",
            str(obj),
        ],
        check=True,
        capture_output=True,
    )
    dumped: subprocess.CompletedProcess[str] = subprocess.run(
        ["llvm-objdump", "-d", str(obj)],
        check=True,
        capture_output=True,
        text=True,
    )
    bodies: dict[str, list[int]] = {}
    listing: dict[str, list[str]] = {}
    current: str | None = None
    for line in dumped.stdout.splitlines():
        matched_func: re.Match[str] | None = FUNC_RE.match(line)
        if matched_func is not None:
            current = matched_func.group(1)
            bodies[current] = []
            listing[current] = []
            continue
        if current is None:
            continue
        matched_insn: re.Match[str] | None = INSN_RE.match(line)
        if matched_insn is None:
            continue
        bodies[current].extend(int(matched_insn.group(1), 16).to_bytes(4, "little"))
        listing[current].append(" ".join(matched_insn.group(2).split()))
    populated: dict[str, list[int]] = {
        name: body for name, body in bodies.items() if body
    }
    version: subprocess.CompletedProcess[str] = subprocess.run(
        ["clang", "--version"],
        check=True,
        capture_output=True,
        text=True,
    )
    return (
        populated,
        {name: listing[name] for name in populated},
        version.stdout.splitlines()[0].strip(),
    )


def render(
    bodies: dict[str, list[int]], listing: dict[str, list[str]], toolchain: str, /
) -> str:
    rows: list[str] = []
    for name, body in bodies.items():
        byte_text: str = ", ".join(f"0x{value:02x}" for value in body)
        reference: str = " ; ".join(listing[name]).replace("\\", "\\\\").replace('"', '\\"')
        rows.append(f'    ("{name}", &[{byte_text}], "{reference}"),')
    if not toolchain:
        raise SystemExit("the assembler reported no version string")
    return (
        "pub(crate) const SWEEP_CASES: &[(&str, &[u8], &str)] = &[\n"
        + "\n".join(rows)
        + "\n];\n"
    )


def main() -> int:
    if ARCH_DIRECTIVE not in SRC.read_text(encoding="utf-8"):
        raise SystemExit(
            f"sweep.s must keep the {ARCH_DIRECTIVE!r} directive or gated encodings vanish"
        )
    with tempfile.TemporaryDirectory() as raw_dir:
        bodies, listing, toolchain = assemble(Path(raw_dir))
    if not bodies:
        raise SystemExit("the sweep produced no function bodies")
    rendered: str = render(bodies, listing, toolchain)
    if "--check" in sys.argv:
        existing: str = OUT.read_text(encoding="utf-8")
        if existing != rendered:
            raise SystemExit(f"{OUT} is stale; rerun gen_sweep.py")
        print(f"sweep_fresh functions={len(bodies)} toolchain={toolchain}")
        return 0
    OUT.write_text(rendered, encoding="utf-8")
    digest: str = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    print(f"sweep_sha256={digest} functions={len(bodies)} toolchain={toolchain}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
