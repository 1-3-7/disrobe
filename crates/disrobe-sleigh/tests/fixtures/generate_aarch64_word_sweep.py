from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

TRIPLE = "aarch64-none-elf"
SWEEP_SEED = 0x5150202406127A11
RANDOM_WORDS_PER_GROUP = 192
MAX_SWEEP_WORDS = 8192
CORPUS_NAMES = ("aarch64_forms", "aarch64_oracle_o0", "aarch64_oracle_o2")
GROUP_OP0: tuple[tuple[str, tuple[int, ...]], ...] = (
    ("reserved", (0b0000,)),
    ("unallocated_0001", (0b0001,)),
    ("sve", (0b0010,)),
    ("unallocated_0011", (0b0011,)),
    ("dp_immediate", (0b1000, 0b1001)),
    ("branch_system", (0b1010, 0b1011)),
    ("load_store", (0b0100, 0b0110, 0b1100, 0b1110)),
    ("dp_register", (0b0101, 0b1101)),
    ("dp_simd_fp", (0b0111, 0b1111)),
)
BOUNDARY_FIELDS: tuple[tuple[int, int], ...] = (
    (0, 5),
    (5, 5),
    (16, 5),
    (10, 6),
    (16, 6),
    (10, 12),
    (22, 2),
)
LISTING = re.compile(r"^\s*[0-9a-f]+:\s+([0-9a-f]{8})\s+(.*)$")
SYMBOL_SUFFIX = re.compile(r"\s*<[^>]*>")
MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1


@dataclass
class SplitMix:
    state: int

    def next_value(self: SplitMix, /) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK64
        value = self.state
        value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK64
        return value ^ (value >> 31)


def corpus_words(corpus: Path, /) -> list[int]:
    words: list[int] = []
    for name in CORPUS_NAMES:
        data: bytes = (corpus / f"{name}.text").read_bytes()
        for offset in range(0, len(data) - 3, 4):
            words.append(int.from_bytes(data[offset : offset + 4], "little"))
    return words


def boundary_variants(words: list[int], /) -> list[int]:
    variants: list[int] = []
    for word in sorted(set(words)):
        for shift, width in BOUNDARY_FIELDS:
            field: int = ((1 << width) - 1) << shift
            variants.append(word & ~field & MASK32)
            variants.append((word | field) & MASK32)
    return variants


def random_words() -> list[int]:
    generator: SplitMix = SplitMix(SWEEP_SEED)
    words: list[int] = []
    for _, op0_values in GROUP_OP0:
        for _ in range(RANDOM_WORDS_PER_GROUP):
            draw: int = generator.next_value()
            selected: int = op0_values[(draw >> 40) % len(op0_values)]
            words.append(((draw & MASK32) & ~(0xF << 25)) | (selected << 25))
    return words


def sweep_words(corpus: Path, /) -> list[int]:
    base: list[int] = corpus_words(corpus)
    every: list[int] = base + boundary_variants(base) + random_words()
    unique: list[int] = sorted(set(every))
    if len(unique) > MAX_SWEEP_WORDS:
        raise SystemExit(f"sweep word count {len(unique)} exceeds {MAX_SWEEP_WORDS}")
    return unique


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
    source: Path = scratch / "sweep.s"
    obj: Path = scratch / "sweep.o"
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
        raise SystemExit("llvm-objdump listing does not cover every sweep word in order")
    return rendered


def main() -> None:
    fixtures: Path = Path(__file__).resolve().parent
    corpus: Path = fixtures.parent / "corpus"
    scratch: Path = Path(tempfile.mkdtemp(prefix="disrobe-sleigh-word-sweep-"))
    clang: Path = find_tool("DISROBE_CLANG", "clang")
    objdump: Path = find_tool("DISROBE_LLVM_OBJDUMP", "llvm-objdump")
    version: str = tool_version(objdump)
    words: list[int] = sweep_words(corpus)
    rendered: list[str] = disassemble(clang, objdump, words, scratch)
    body: list[str] = [f"llvm-objdump {version} {TRIPLE}"]
    body.extend(f"{word:08x}\t{text}" for word, text in zip(words, rendered, strict=True))
    target: Path = corpus / "aarch64_word_sweep.llvm"
    target.write_text("\n".join(body) + "\n", encoding="ascii", newline="\n")
    accepted: int = sum(1 for text in rendered if text != "<unknown>")
    print(f"words {len(words)} reference-accepted {accepted} written {target}", file=sys.stderr)


if __name__ == "__main__":
    main()
