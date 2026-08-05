from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Final

import unicorn
from unicorn import UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, Uc, UcError
from unicorn import x86_const

VERSION: Final[str] = "2.1.4"
IMAGE_BASE: Final[int] = 0x1000
IMAGE_BYTES: Final[int] = 0x3000
RESERVED_FLAG: Final[int] = 0x2
OBSERVED_FLAGS: Final[int] = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 10) | (1 << 11)

REGISTERS: Final[tuple[int, ...]] = (
    x86_const.UC_X86_REG_RAX,
    x86_const.UC_X86_REG_RCX,
    x86_const.UC_X86_REG_RDX,
    x86_const.UC_X86_REG_RBX,
    x86_const.UC_X86_REG_RSP,
    x86_const.UC_X86_REG_RBP,
    x86_const.UC_X86_REG_RSI,
    x86_const.UC_X86_REG_RDI,
    x86_const.UC_X86_REG_R8,
    x86_const.UC_X86_REG_R9,
    x86_const.UC_X86_REG_R10,
    x86_const.UC_X86_REG_R11,
    x86_const.UC_X86_REG_R12,
    x86_const.UC_X86_REG_R13,
    x86_const.UC_X86_REG_R14,
    x86_const.UC_X86_REG_R15,
)


class Case:
    __slots__ = ("code", "flags", "patch", "registers", "rip")

    def __init__(
        self: Case,
        code: bytes,
        registers: tuple[int, ...],
        flags: int,
        rip: int,
        patch: tuple[tuple[int, bytes], ...],
        /,
    ) -> None:
        self.code = code
        self.registers = registers
        self.flags = flags
        self.rip = rip
        self.patch = patch


def parse_cases(text: str, /) -> list[Case]:
    cases: list[Case] = []
    for line in text.splitlines():
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 6:
            raise RuntimeError(f"malformed case record: {line}")
        code = bytes.fromhex(fields[1])
        registers = tuple(int(value, 16) for value in fields[2].split(","))
        if len(registers) != len(REGISTERS):
            raise RuntimeError(f"malformed register record: {line}")
        patch: tuple[tuple[int, bytes], ...] = ()
        if fields[5] != "-":
            entries: list[tuple[int, bytes]] = []
            for record in fields[5].split(","):
                address, payload = record.split(":")
                entries.append((int(address, 16), bytes.fromhex(payload)))
            patch = tuple(entries)
        cases.append(Case(code, registers, int(fields[3], 16), int(fields[4], 16), patch))
    return cases


def new_machine(image: bytes, /) -> Uc:
    machine = Uc(UC_ARCH_X86, UC_MODE_64)
    machine.mem_map(IMAGE_BASE, IMAGE_BYTES, UC_PROT_ALL)
    machine.mem_write(IMAGE_BASE, image)
    return machine


def render(case: Case, before: bytes, registers: tuple[int, ...], flags: int, rip: int, memory: bytes, /) -> str:
    parts: list[str] = [f"ip={rip:x}", f"f={flags & OBSERVED_FLAGS:x}"]
    for index, value in enumerate(registers):
        if value != case.registers[index]:
            parts.append(f"r{index}={value:x}")
    if memory != before:
        parts.extend(
            f"m{IMAGE_BASE + offset:x}={memory[offset]:02x}"
            for offset in range(len(memory))
            if memory[offset] != before[offset]
        )
    return "|".join(parts)


def execute(machine: Uc, case: Case, image: bytes, /) -> tuple[str, Uc]:
    machine.mem_write(IMAGE_BASE, image)
    machine.mem_write(case.rip, case.code)
    for address, payload in case.patch:
        machine.mem_write(address, payload)
    for slot, value in zip(REGISTERS, case.registers, strict=True):
        machine.reg_write(slot, value)
    machine.reg_write(x86_const.UC_X86_REG_EFLAGS, RESERVED_FLAG | (case.flags & OBSERVED_FLAGS))
    try:
        machine.emu_start(case.rip, case.rip + len(case.code), 0, 1)
    except UcError as error:
        status = "reject" if error.errno == unicorn.UC_ERR_INSN_INVALID else "fault"
        return f"{status}\t-", new_machine(image)
    produced = tuple(machine.reg_read(slot) for slot in REGISTERS)
    flags = machine.reg_read(x86_const.UC_X86_REG_EFLAGS)
    rip = machine.reg_read(x86_const.UC_X86_REG_RIP)
    memory = bytes(machine.mem_read(IMAGE_BASE, IMAGE_BYTES))
    patched = bytearray(image)
    patched[case.rip - IMAGE_BASE : case.rip - IMAGE_BASE + len(case.code)] = case.code
    for address, payload in case.patch:
        patched[address - IMAGE_BASE : address - IMAGE_BASE + len(payload)] = payload
    return f"ok\t{render(case, bytes(patched), produced, flags, rip, memory)}", machine


def main() -> None:
    if unicorn.__version__ != VERSION:
        raise RuntimeError(f"unicorn {VERSION} required, found {unicorn.__version__}")
    if len(sys.argv) != 4:
        raise RuntimeError("usage: unicorn_oracle.py IMAGE CASES OUTPUT")
    image = Path(sys.argv[1]).resolve(strict=True).read_bytes()
    if len(image) != IMAGE_BYTES:
        raise RuntimeError(f"image must be {IMAGE_BYTES} bytes")
    request = Path(sys.argv[2]).resolve(strict=True).read_bytes()
    output = Path(sys.argv[3]).resolve()
    cases = parse_cases(request.decode("utf-8"))
    digest = hashlib.sha256(request).hexdigest()
    machine = new_machine(image)
    lines: list[str] = [
        f"# unicorn {VERSION}",
        "# arch x86-64",
        f"# cases {len(cases)}",
        f"# digest {digest}",
    ]
    for case in cases:
        rendered, machine = execute(machine, case, image)
        lines.append(rendered)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
