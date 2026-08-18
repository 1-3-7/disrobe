from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TRIPLE = "aarch64-none-elf"
LISTING = re.compile(r"^\s*[0-9a-f]+:\s+([0-9a-f]{8})\s+(.*)$")
SYMBOL_SUFFIX = re.compile(r"\s*<[^>]*>")
MASK32 = (1 << 32) - 1

WIDTHS: tuple[tuple[int, int, int, int], ...] = (
    (1, 0b00, 0b01, 0b00),
    (2, 0b01, 0b01, 0b00),
    (4, 0b10, 0b01, 0b00),
    (8, 0b11, 0b01, 0b00),
    (16, 0b00, 0b11, 0b10),
)

POST_INDEX = 0b01
PRE_INDEX = 0b11

FORMS: tuple[tuple[str, int], ...] = (
    ("post_positive", 8),
    ("post_negative", -8),
    ("pre_positive", 8),
    ("pre_negative", -8),
    ("unsigned_offset", 3),
    ("unsigned_zero", 0),
)


def indexed_word(size: int, opc: int, imm9: int, mode: int, rn: int, rt: int, /) -> int:
    encoded: int = imm9 & 0x1FF
    return (
        (size << 30)
        | (0b111 << 27)
        | (1 << 26)
        | (0b00 << 24)
        | (opc << 22)
        | (0 << 21)
        | (encoded << 12)
        | (mode << 10)
        | (rn << 5)
        | rt
    ) & MASK32


def unsigned_word(size: int, opc: int, imm12: int, rn: int, rt: int, /) -> int:
    return (
        (size << 30)
        | (0b111 << 27)
        | (1 << 26)
        | (0b01 << 24)
        | (opc << 22)
        | ((imm12 & 0xFFF) << 10)
        | (rn << 5)
        | rt
    ) & MASK32


def matrix_words() -> list[int]:
    words: list[int] = []
    index: int = 0
    for _, size, load_opc, store_opc in WIDTHS:
        for form, immediate in FORMS:
            for opc in (load_opc, store_opc):
                rt: int = (index * 7) % 32
                rn: int = (index * 11 + 3) % 32
                if form.startswith("post"):
                    words.append(indexed_word(size, opc, immediate, POST_INDEX, rn, rt))
                elif form.startswith("pre"):
                    words.append(indexed_word(size, opc, immediate, PRE_INDEX, rn, rt))
                else:
                    words.append(unsigned_word(size, opc, immediate, rn, rt))
                index += 1
    return words


def find_tool(variable: str, name: str, /) -> Path:
    override: str | None = os.environ.get(variable)
    if override is not None and Path(override).is_file():
        return Path(override)
    found: str | None = shutil.which(name)
    if found is None:
        raise SystemExit(f"{name} not found; set {variable}")
    return Path(found)


def tool_version(objdump: Path, /) -> str:
    output: str = subprocess.run(
        [str(objdump), "--version"], capture_output=True, text=True, check=True
    ).stdout
    for line in output.splitlines():
        stripped: str = line.strip()
        if stripped.startswith("LLVM version "):
            return stripped[len("LLVM version ") :]
    raise SystemExit("llvm-objdump did not report an LLVM version")


def normalize(body: str, /) -> str:
    if body.startswith("<unknown>"):
        return "<unknown>"
    text: str = SYMBOL_SUFFIX.sub("", body.split("//")[0])
    return " ".join(text.split())


def disassemble(clang: Path, objdump: Path, words: list[int], scratch: Path, /) -> list[str]:
    source: Path = scratch / "matrix.s"
    obj: Path = scratch / "matrix.o"
    lines: list[str] = [".text"]
    lines.extend(f".inst 0x{word:08x}" for word in words)
    source.write_text("\n".join(lines) + "\n", encoding="ascii")
    subprocess.run(
        [str(clang), f"--target={TRIPLE}", "-c", "-o", str(obj), str(source)], check=True
    )
    listing: str = subprocess.run(
        [str(objdump), "-d", str(obj)], capture_output=True, text=True, check=True
    ).stdout
    rendered: list[str] = []
    encodings: list[int] = []
    for line in listing.splitlines():
        matched: re.Match[str] | None = LISTING.match(line)
        if matched is None:
            continue
        encodings.append(int(matched.group(1), 16))
        rendered.append(normalize(matched.group(2).strip()))
    if encodings != words:
        raise SystemExit("llvm-objdump listing does not cover every matrix word in order")
    return rendered


def main() -> None:
    fixtures: Path = Path(__file__).resolve().parent
    corpus: Path = fixtures.parent / "corpus"
    scratch: Path = Path(tempfile.mkdtemp(prefix="disrobe-sleigh-scalar-fp-matrix-"))
    clang: Path = find_tool("DISROBE_CLANG", "clang")
    objdump: Path = find_tool("DISROBE_LLVM_OBJDUMP", "llvm-objdump")
    version: str = tool_version(objdump)
    words: list[int] = matrix_words()
    rendered: list[str] = disassemble(clang, objdump, words, scratch)
    body: list[str] = [f"llvm-objdump {version} {TRIPLE}"]
    body.extend(f"{word:08x}\t{text}" for word, text in zip(words, rendered, strict=True))
    target: Path = corpus / "aarch64_scalar_fp_matrix.llvm"
    target.write_text("\n".join(body) + "\n", encoding="ascii", newline="\n")
    rejected: int = sum(1 for text in rendered if text == "<unknown>")
    print(f"words {len(words)} reference-rejected {rejected} written {target}", file=sys.stderr)


if __name__ == "__main__":
    main()
