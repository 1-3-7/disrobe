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

RISCV_REGISTERS = {
    "zero",
    "ra",
    "sp",
    "gp",
    "tp",
    "t0",
    "t1",
    "t2",
    "s0",
    "s1",
    "a0",
    "a1",
    "a2",
    "a3",
    "a4",
    "a5",
    "a6",
    "a7",
    "s2",
    "s3",
    "s4",
    "s5",
    "s6",
    "s7",
    "s8",
    "s9",
    "s10",
    "s11",
    "t3",
    "t4",
    "t5",
    "t6",
    "pc",
}

POWERPC_REGISTERS = {
    "xer_so",
    "LR",
    "CTR",
    "pc",
    *(f"r{index}" for index in range(32)),
    *(f"cr{index}" for index in range(8)),
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
    Corpus(
        "riscv32",
        "RISCV:LE:32:default",
        "riscv32_forms.text",
        (
            Sample(0, 4, "addi"),
            Sample(4, 4, "add"),
            Sample(8, 4, "sub"),
            Sample(12, 4, "and"),
            Sample(16, 4, "or"),
            Sample(20, 4, "xor"),
            Sample(24, 4, "sll"),
            Sample(28, 4, "srl"),
            Sample(32, 4, "sra"),
            Sample(36, 4, "slt"),
            Sample(40, 4, "lw"),
            Sample(44, 4, "sw"),
            Sample(48, 4, "lui"),
            Sample(52, 4, "auipc"),
            Sample(56, 4, "beq"),
            Sample(60, 4, "bne"),
            Sample(64, 4, "blt"),
            Sample(68, 4, "bge"),
            Sample(72, 4, "jal"),
            Sample(76, 4, "jalr"),
            Sample(80, 4, "mul"),
            Sample(84, 4, "mulh"),
            Sample(88, 4, "mulhsu"),
            Sample(92, 4, "mulhu"),
            Sample(112, 4, "nop"),
            Sample(116, 4, "ret"),
            Sample(120, 4, "addi"),
        ),
    ),
    Corpus(
        "riscv64",
        "RISCV:LE:64:default",
        "riscv64_forms.text",
        (
            Sample(0, 4, "addi"),
            Sample(4, 4, "add"),
            Sample(8, 4, "sub"),
            Sample(12, 4, "and"),
            Sample(16, 4, "or"),
            Sample(20, 4, "xor"),
            Sample(24, 4, "sll"),
            Sample(28, 4, "srl"),
            Sample(32, 4, "sra"),
            Sample(36, 4, "slt"),
            Sample(40, 4, "lw"),
            Sample(44, 4, "sw"),
            Sample(48, 4, "ld"),
            Sample(52, 4, "sd"),
            Sample(56, 4, "lui"),
            Sample(60, 4, "auipc"),
            Sample(64, 4, "beq"),
            Sample(68, 4, "bne"),
            Sample(72, 4, "blt"),
            Sample(76, 4, "bge"),
            Sample(80, 4, "jal"),
            Sample(84, 4, "jalr"),
            Sample(88, 4, "mul"),
            Sample(92, 4, "mulh"),
            Sample(96, 4, "mulhsu"),
            Sample(100, 4, "mulhu"),
            Sample(120, 4, "nop"),
            Sample(124, 4, "ret"),
            Sample(128, 4, "addi"),
        ),
    ),
    Corpus(
        "riscv32c",
        "RISCV:LE:32:default",
        "riscv32c_forms.text",
        (
            Sample(0, 2, "addi"),
            Sample(2, 2, "li"),
            Sample(4, 2, "lw"),
            Sample(6, 2, "sw"),
            Sample(8, 2, "j"),
            Sample(10, 2, "jal"),
            Sample(12, 2, "jr"),
            Sample(14, 2, "jalr"),
            Sample(16, 2, "beqz"),
            Sample(18, 2, "bnez"),
            Sample(20, 2, "mv"),
            Sample(22, 2, "add"),
            Sample(24, 2, "nop"),
            Sample(26, 2, "addi"),
            Sample(28, 2, "lw"),
            Sample(30, 2, "sw"),
            Sample(32, 2, "and"),
            Sample(34, 2, "or"),
            Sample(36, 2, "addi"),
        ),
    ),
    Corpus(
        "riscv64c",
        "RISCV:LE:64:default",
        "riscv64c_forms.text",
        (
            Sample(0, 2, "addi"),
            Sample(2, 2, "li"),
            Sample(4, 2, "lw"),
            Sample(6, 2, "sw"),
            Sample(8, 2, "ld"),
            Sample(10, 2, "sd"),
            Sample(12, 2, "j"),
            Sample(14, 2, "jr"),
            Sample(16, 2, "jalr"),
            Sample(18, 2, "beqz"),
            Sample(20, 2, "bnez"),
            Sample(22, 2, "mv"),
            Sample(24, 2, "add"),
            Sample(26, 2, "nop"),
            Sample(28, 2, "addi"),
            Sample(30, 2, "lw"),
            Sample(32, 2, "sw"),
            Sample(34, 2, "and"),
            Sample(36, 2, "or"),
            Sample(38, 2, "addi"),
        ),
    ),
    Corpus(
        "riscv32a",
        "RISCV:LE:32:default",
        "riscv32a_forms.text",
        (
            Sample(0, 4, "lr.w"),
            Sample(4, 4, "lr.w.aq"),
            Sample(8, 4, "sc.w.rl"),
            Sample(12, 4, "amoswap.w"),
            Sample(16, 4, "amoadd.w.aqrl"),
            Sample(20, 4, "amoand.w"),
            Sample(24, 4, "amoor.w"),
            Sample(28, 4, "amoxor.w"),
            Sample(32, 4, "amomin.w"),
            Sample(36, 4, "amomax.w"),
        ),
    ),
    Corpus(
        "riscv64a",
        "RISCV:LE:64:default",
        "riscv64a_forms.text",
        (
            Sample(0, 4, "lr.w"),
            Sample(4, 4, "sc.w"),
            Sample(8, 4, "amoadd.w.aq"),
            Sample(12, 4, "lr.d.rl"),
            Sample(16, 4, "sc.d.aqrl"),
            Sample(20, 4, "amoswap.d"),
            Sample(24, 4, "amoadd.d"),
            Sample(28, 4, "amoand.d"),
            Sample(32, 4, "amoor.d"),
            Sample(36, 4, "amoxor.d"),
            Sample(40, 4, "amomin.d"),
            Sample(44, 4, "amomax.d"),
        ),
    ),
    Corpus(
        "powerpc32",
        "PowerPC:BE:32:default",
        "powerpc32_forms.text",
        (
            Sample(0, 4, "add"),
            Sample(4, 4, "subf"),
            Sample(8, 4, "and"),
            Sample(12, 4, "or"),
            Sample(16, 4, "xor"),
            Sample(20, 4, "slw"),
            Sample(24, 4, "srw"),
            Sample(28, 4, "cmpw"),
            Sample(32, 4, "cmpwi"),
            Sample(36, 4, "lwz"),
            Sample(40, 4, "stw"),
            Sample(44, 4, "lbz"),
            Sample(48, 4, "stb"),
            Sample(52, 4, "li"),
            Sample(56, 4, "lis"),
            Sample(60, 4, "addi"),
            Sample(64, 4, "b"),
            Sample(68, 4, "bl"),
            Sample(72, 4, "bl"),
            Sample(76, 4, "bclr"),
            Sample(80, 4, "ba"),
            Sample(84, 4, "bla"),
            Sample(88, 4, "blr"),
            Sample(92, 4, "bctr"),
            Sample(96, 4, "beq"),
            Sample(100, 4, "bne"),
            Sample(104, 4, "bdnz"),
            Sample(108, 4, "bdzt"),
            Sample(112, 4, "mullw"),
            Sample(120, 4, "nop"),
            Sample(124, 4, "addi"),
        ),
    ),
    Corpus(
        "powerpc64",
        "PowerPC:BE:64:default",
        "powerpc64_forms.text",
        (
            Sample(0, 4, "ld"),
            Sample(4, 4, "std"),
            Sample(8, 4, "rldicl"),
            Sample(12, 4, "rldicr"),
            Sample(16, 4, "cmpd"),
            Sample(20, 4, "cmpld"),
            Sample(24, 4, "mulld"),
            Sample(28, 4, "divd"),
            Sample(32, 4, "beq"),
            Sample(36, 4, "bdnz"),
            Sample(40, 4, "blr"),
            Sample(44, 4, "addi"),
            Sample(48, 4, "add"),
            Sample(52, 4, "subf"),
            Sample(56, 4, "and"),
            Sample(60, 4, "or"),
            Sample(64, 4, "xor"),
            Sample(68, 4, "slw"),
            Sample(72, 4, "srw"),
            Sample(76, 4, "cmpw"),
            Sample(80, 4, "cmpwi"),
            Sample(84, 4, "lwz"),
            Sample(88, 4, "stw"),
            Sample(92, 4, "lbz"),
            Sample(96, 4, "stb"),
            Sample(100, 4, "li"),
            Sample(104, 4, "lis"),
            Sample(108, 4, "mullw"),
            Sample(112, 4, "divw"),
            Sample(116, 4, "nop"),
        ),
    ),
)


def select_registers(language: str) -> None:
    oracle.LITTLE_ENDIAN = ":LE:" in language
    oracle.ADDRESS_SIZE = 8 if ":64:" in language else 4
    if language.startswith("ARM:"):
        names = ARM_REGISTERS
    elif language.startswith("MIPS:"):
        names = MIPS_REGISTERS
    elif language.startswith("PowerPC:"):
        names = POWERPC_REGISTERS
    else:
        names = RISCV_REGISTERS

    def architectural_register(node: object) -> bool:
        return node.space.name == "register" and node.getRegisterName() in names

    oracle.architectural_register = architectural_register


def canonical_mnemonic(mnemonic: str) -> str:
    base = mnemonic.removeprefix("c.")
    return {
        "addi4spn": "addi",
        "lwsp": "lw",
        "swsp": "sw",
    }.get(base, base)


def mnemonic_matches(observed: str, expected: str) -> bool:
    aliases = {
        ("ldmia", "pop"),
        ("blr", "bclr"),
        ("ori", "nop"),
    }
    return canonical_mnemonic(observed) == expected or (observed, expected) in aliases


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
            disassembly = context.disassemble(
                encoded,
                base_address=sample.address,
                max_instructions=1,
            )
            if len(disassembly.instructions) != 1:
                raise RuntimeError(f"disassembly count {corpus.key} {sample.address:x}")
            instruction = disassembly.instructions[0]
            if not mnemonic_matches(instruction.mnem, sample.mnemonic):
                raise RuntimeError(
                    f"mnemonic mismatch {corpus.key} {sample.address:x} "
                    f"{instruction.mnem} != {sample.mnemonic}"
                )
            expected_length = 4 if corpus.language.startswith("MIPS:") else sample.length
            if instruction.length != expected_length:
                raise RuntimeError(
                    f"disassembly mismatch {corpus.key} {sample.address:x} "
                    f"{instruction.length}"
                )
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
