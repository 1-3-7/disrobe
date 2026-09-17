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

SCALAR_WIDTHS: tuple[tuple[int, int, int], ...] = (
    (0b00, 0b01, 0b00),
    (0b01, 0b01, 0b00),
    (0b10, 0b01, 0b00),
    (0b11, 0b01, 0b00),
    (0b00, 0b11, 0b10),
)

PAIR_WIDTHS: tuple[int, ...] = (0b00, 0b01, 0b10)
EXTEND_OPTIONS: tuple[int, ...] = (0b010, 0b011, 0b110, 0b111)
UNSCALED_IMMEDIATES: tuple[int, ...] = (8, -8, 0)
PAIR_IMMEDIATES: tuple[int, ...] = (2, -2, 0)
LITERAL_IMMEDIATES: tuple[int, ...] = (4, -4)
GENERAL_SIZES: tuple[int, ...] = (0b10, 0b11)
GENERAL_MODES: tuple[int, ...] = (0b00, 0b01, 0b11)


def unscaled_word(size: int, opc: int, imm9: int, rn: int, rt: int, /) -> int:
    return (
        (size << 30) | (0b111 << 27) | (1 << 26) | (opc << 22) | ((imm9 & 0x1FF) << 12) | (rn << 5) | rt
    ) & MASK32


def register_word(size: int, opc: int, rm: int, option: int, scaled: int, rn: int, rt: int, /) -> int:
    return (
        (size << 30)
        | (0b111 << 27)
        | (1 << 26)
        | (opc << 22)
        | (1 << 21)
        | (rm << 16)
        | (option << 13)
        | (scaled << 12)
        | (0b10 << 10)
        | (rn << 5)
        | rt
    ) & MASK32


def literal_word(opc: int, imm19: int, rt: int, /) -> int:
    return ((opc << 30) | (0b011 << 27) | (1 << 26) | ((imm19 & 0x7FFFF) << 5) | rt) & MASK32


def pair_word(opc: int, mode: int, load: int, imm7: int, rt2: int, rn: int, rt: int, /) -> int:
    return (
        (opc << 30)
        | (0b101 << 27)
        | (1 << 26)
        | (mode << 23)
        | (load << 22)
        | ((imm7 & 0x7F) << 15)
        | (rt2 << 10)
        | (rn << 5)
        | rt
    ) & MASK32


def general_word(size: int, opc: int, imm9: int, mode: int, rn: int, rt: int, /) -> int:
    return (
        (size << 30)
        | (0b111 << 27)
        | (opc << 22)
        | ((imm9 & 0x1FF) << 12)
        | (mode << 10)
        | (rn << 5)
        | rt
    ) & MASK32


def matrix_words() -> list[int]:
    words: list[int] = []
    index: int = 0

    def registers() -> tuple[int, int]:
        nonlocal index
        chosen = ((index * 7) % 32, (index * 11 + 3) % 32)
        index += 1
        return chosen

    for size, load_opc, store_opc in SCALAR_WIDTHS:
        for immediate in UNSCALED_IMMEDIATES:
            for opc in (load_opc, store_opc):
                rt, rn = registers()
                words.append(unscaled_word(size, opc, immediate, rn, rt))
    for size, load_opc, store_opc in SCALAR_WIDTHS:
        for option in EXTEND_OPTIONS:
            for scaled in (0, 1):
                for opc in (load_opc, store_opc):
                    rt, rn = registers()
                    rm = (index * 5) % 31
                    words.append(register_word(size, opc, rm, option, scaled, rn, rt))
    for opc in (0b00, 0b01, 0b10):
        for immediate in LITERAL_IMMEDIATES:
            rt, _ = registers()
            words.append(literal_word(opc, immediate, rt))
    for opc in PAIR_WIDTHS:
        for mode in (0b01, 0b10, 0b11):
            for immediate in PAIR_IMMEDIATES:
                for load in (1, 0):
                    rt, rn = registers()
                    rt2 = (index * 13 + 5) % 32
                    words.append(pair_word(opc, mode, load, immediate, rt2, rn, rt))
    for size in GENERAL_SIZES:
        for mode in GENERAL_MODES:
            for immediate in UNSCALED_IMMEDIATES:
                for opc in (0b01, 0b00):
                    rt, rn = registers()
                    words.append(general_word(size, opc, immediate, mode, rn, rt))
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
    scratch: Path = Path(tempfile.mkdtemp(prefix="disrobe-sleigh-memory-matrix-"))
    clang: Path = find_tool("DISROBE_CLANG", "clang")
    objdump: Path = find_tool("DISROBE_LLVM_OBJDUMP", "llvm-objdump")
    version: str = tool_version(objdump)
    words: list[int] = matrix_words()
    rendered: list[str] = disassemble(clang, objdump, words, scratch)
    body: list[str] = [f"llvm-objdump {version} {TRIPLE}"]
    body.extend(f"{word:08x}\t{text}" for word, text in zip(words, rendered, strict=True))
    target: Path = corpus / "aarch64_memory_matrix.llvm"
    target.write_text("\n".join(body) + "\n", encoding="ascii", newline="\n")
    rejected: int = sum(1 for text in rendered if text == "<unknown>")
    print(f"words {len(words)} reference-rejected {rejected} written {target}", file=sys.stderr)


if __name__ == "__main__":
    main()
