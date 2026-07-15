from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import pypcode

import generate_pypcode_oracle as oracle


VERSION = "4.0.0"


@dataclass(frozen=True)
class Sample:
    address: int
    length: int
    mnemonic: str


@dataclass(frozen=True)
class Corpus:
    key: str
    language: str
    name: str
    samples: tuple[Sample, ...]


ARM_REGISTERS = {
    "NG",
    "ZR",
    "CY",
    "OV",
    "sp",
    "lr",
    "pc",
    *(f"r{index}" for index in range(13)),
}

MIPS_REGISTERS = {
    "zero",
    "at",
    "v0",
    "v1",
    "a0",
    "a1",
    "a2",
    "a3",
    "t0",
    "t1",
    "t2",
    "t3",
    "t4",
    "t5",
    "t6",
    "t7",
    "s0",
    "s1",
    "s2",
    "s3",
    "s4",
    "s5",
    "s6",
    "s7",
    "t8",
    "t9",
    "k0",
    "k1",
    "gp",
    "sp",
    "s8",
    "ra",
    "hi",
    "lo",
    "pc",
}


CORPORA = (
    Corpus(
        "arm32-a32",
        "ARM:LE:32:v7",
        "arm32_a32_forms.text",
        (
            Sample(0, 4, "add"),
            Sample(24, 4, "movw"),
            Sample(32, 4, "mul"),
            Sample(44, 4, "ldr"),
            Sample(48, 4, "str"),
            Sample(64, 4, "bl"),
            Sample(68, 4, "bx"),
            Sample(76, 4, "pop"),
        ),
    ),
    Corpus(
        "arm32-thumb",
        "ARM:LE:32:v8T",
        "arm32_thumb_forms.text",
        (
            Sample(0, 2, "adds"),
            Sample(12, 2, "movs"),
            Sample(14, 4, "movw"),
            Sample(26, 2, "ldr"),
            Sample(28, 2, "str"),
            Sample(36, 4, "bl"),
            Sample(40, 2, "bx"),
            Sample(44, 2, "pop"),
            Sample(46, 2, "mov"),
            Sample(48, 2, "mov"),
            Sample(50, 2, "add"),
        ),
    ),
    Corpus(
        "mips32le",
        "MIPS:LE:32:default",
        "mips32le_forms.text",
        (
            Sample(4, 4, "addu"),
            Sample(8, 4, "addiu"),
            Sample(40, 4, "lw"),
            Sample(44, 4, "sw"),
            Sample(48, 4, "lui"),
            Sample(52, 8, "beq"),
        ),
    ),
    Corpus(
        "mips32be",
        "MIPS:BE:32:default",
        "mips32be_forms.text",
        (
            Sample(4, 4, "addu"),
            Sample(8, 4, "addiu"),
            Sample(40, 4, "lw"),
            Sample(44, 4, "sw"),
            Sample(48, 4, "lui"),
            Sample(52, 8, "beq"),
        ),
    ),
)


def select_registers(language: str) -> None:
    names = ARM_REGISTERS if language.startswith("ARM:") else MIPS_REGISTERS

    def architectural_register(node: object) -> bool:
        return node.space.name == "register" and node.getRegisterName() in names

    oracle.architectural_register = architectural_register


def main() -> None:
    if pypcode.__version__ != VERSION:
        raise RuntimeError(f"pypcode {VERSION} required")
    tests = Path(__file__).resolve().parent.parent
    corpus_directory = tests / "corpus"
    raw_lines = [f"pypcode {VERSION}"]
    table_lines = ["language\taddress\tbytes\tmnemonic\tnormalized_architectural_facts"]
    for corpus in CORPORA:
        select_registers(corpus.language)
        context = pypcode.Context(corpus.language)
        machine_code = (corpus_directory / corpus.name).read_bytes()
        raw_lines.append(corpus.language)
        for sample in corpus.samples:
            encoded = machine_code[sample.address : sample.address + sample.length]
            if len(encoded) != sample.length:
                raise RuntimeError(f"short sample {corpus.key} {sample.address:x}")
            translation = context.translate(
                encoded,
                base_address=sample.address,
                max_instructions=1,
            )
            raw_lines.append(
                f"{corpus.key} {sample.address:x} {encoded.hex()} {sample.mnemonic}"
            )
            raw_lines.extend(str(translation).splitlines())
            facts = oracle.normalize(list(translation.ops))
            normalized = "|".join(facts) if facts else "none"
            table_lines.append(
                f"{corpus.key}\t{sample.address:x}\t{encoded.hex()}\t{sample.mnemonic}\t{normalized}"
            )
    (corpus_directory / "multiarch_pypcode.raw").write_text(
        "\n".join(raw_lines) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (corpus_directory / "multiarch_pypcode.tsv").write_text(
        "\n".join(table_lines) + "\n",
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    main()
