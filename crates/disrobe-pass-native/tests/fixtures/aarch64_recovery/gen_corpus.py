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
INSN_RE: re.Pattern[str] = re.compile(r"^\s*[0-9a-f]+:\s+([0-9a-f]{8})\s+(\S+)(.*)$")

FUSED: frozenset[str] = frozenset({"fmadd", "fmsub", "fnmadd", "fnmsub"})
FUSED_REQUIRED: dict[str, str] = {
    "fma_madd_f": "fmadd",
    "fma_madd_d": "fmadd",
    "fma_msub_f": "fmsub",
    "fma_msub_d": "fmsub",
    "fma_nmadd_f": "fnmadd",
    "fma_nmadd_d": "fnmadd",
    "fma_nmsub_f": "fnmsub",
    "fma_nmsub_d": "fnmsub",
}
SQRT_REQUIRED: frozenset[str] = frozenset(
    {
        "fs_sqrt_f",
        "fs_sqrt_d",
        "fs_hypot_f",
        "fs_norm3_d",
        "fs_rsqrt_f",
        "fs_sqrt_sum_d",
        "fs_sqrt_scaled_f",
        "fs_sqrt_diff_d",
    }
)
UNFUSED_REQUIRED: dict[str, frozenset[str]] = {
    "mul_add_unfused_f": frozenset({"fmul", "fadd"}),
    "mul_add_unfused_d": frozenset({"fmul", "fadd"}),
    "sub_mul_unfused_f": frozenset({"fmul", "fsub"}),
    "sub_mul_unfused_d": frozenset({"fmul", "fsub"}),
}
FIXED_POINT_REQUIRED: dict[str, tuple[str, str]] = {
    "fx_scvtf_f_w": ("scvtf", "fdiv"),
    "fx_scvtf_d_w": ("scvtf", "fdiv"),
    "fx_scvtf_f_x": ("scvtf", "fdiv"),
    "fx_scvtf_d_x": ("scvtf", "fdiv"),
    "fx_ucvtf_f_w": ("ucvtf", "fdiv"),
    "fx_ucvtf_d_w": ("ucvtf", "fdiv"),
    "fx_ucvtf_f_x": ("ucvtf", "fdiv"),
    "fx_ucvtf_d_x": ("ucvtf", "fdiv"),
    "fx_fcvtzs_w_f": ("fcvtzs", "fmul"),
    "fx_fcvtzs_w_d": ("fcvtzs", "fmul"),
    "fx_fcvtzs_x_f": ("fcvtzs", "fmul"),
    "fx_fcvtzs_x_d": ("fcvtzs", "fmul"),
    "fx_fcvtzu_w_f": ("fcvtzu", "fmul"),
    "fx_fcvtzu_w_d": ("fcvtzu", "fmul"),
    "fx_fcvtzu_x_f": ("fcvtzu", "fmul"),
    "fx_fcvtzu_x_d": ("fcvtzu", "fmul"),
}
FIXED_POINT_FUSED_LEVELS: frozenset[str] = frozenset({"O1", "O2", "O3", "Os"})
FIXED_POINT_TAIL_RE: re.Pattern[str] = re.compile(
    r"^\s*[a-z][0-9]+,\s*[a-z][0-9]+,\s*#(?:0x)?[0-9a-f]+$"
)


def disassemble(
    level: str, out_dir: Path, /
) -> tuple[dict[str, list[int]], dict[str, set[str]], dict[str, set[tuple[str, str]]]]:
    obj: Path = out_dir / f"corpus_{level}.o"
    compile_cmd: list[str] = [
        "clang",
        "--target=aarch64-linux-gnu",
        f"-{level}",
        "-fno-builtin",
        "-fno-math-errno",
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
    mnemonics: dict[str, set[str]] = {}
    encodings: dict[str, set[tuple[str, str]]] = {}
    current: str | None = None
    for line in dumped.stdout.splitlines():
        matched_func: re.Match[str] | None = FUNC_RE.match(line)
        if matched_func is not None:
            name: str = matched_func.group(1)
            current = name
            out[name] = []
            mnemonics[name] = set()
            encodings[name] = set()
            continue
        if current is None:
            continue
        matched_insn: re.Match[str] | None = INSN_RE.match(line)
        if matched_insn is None:
            continue
        word: int = int(matched_insn.group(1), 16)
        out[current].extend(word.to_bytes(4, "little"))
        mnemonics[current].add(matched_insn.group(2))
        encodings[current].add(
            (matched_insn.group(2), matched_insn.group(3).split("//")[0].strip())
        )
    bodies: dict[str, list[int]] = {
        name: body for name, body in out.items() if body
    }
    return (
        bodies,
        {name: mnemonics[name] for name in bodies},
        {name: encodings[name] for name in bodies},
    )


def gate_fixed_point(
    level: str,
    mnemonics: dict[str, set[str]],
    encodings: dict[str, set[tuple[str, str]]],
    /,
) -> None:
    fused_level: bool = level in FIXED_POINT_FUSED_LEVELS
    for name, (mnemonic, split_op) in FIXED_POINT_REQUIRED.items():
        seen: set[str] = mnemonics.get(name, set())
        tails: set[str] = {
            operands
            for opcode, operands in encodings.get(name, set())
            if opcode == mnemonic
        }
        fused: set[str] = {tail for tail in tails if FIXED_POINT_TAIL_RE.match(tail)}
        if mnemonic not in seen:
            raise SystemExit(
                f"corpus gate {level}: {name} must contain {mnemonic}, saw {sorted(seen)}"
            )
        if fused_level:
            if not fused:
                raise SystemExit(
                    f"corpus gate {level}: {name} must fuse the fractional immediate into"
                    f" {mnemonic}, saw operand tails {sorted(tails)}"
                )
            if split_op in seen:
                raise SystemExit(
                    f"corpus gate {level}: {name} must fold the scaling into {mnemonic},"
                    f" saw a separate {split_op}"
                )
            continue
        if fused:
            raise SystemExit(
                f"corpus gate {level}: {name} is not expected to fuse at {level},"
                f" saw operand tails {sorted(fused)}"
            )
        if split_op not in seen:
            raise SystemExit(
                f"corpus gate {level}: {name} must keep a separate {split_op} at {level},"
                f" saw {sorted(seen)}"
            )


def gate(level: str, mnemonics: dict[str, set[str]], /) -> None:
    for name, required in FUSED_REQUIRED.items():
        seen: set[str] = mnemonics.get(name, set())
        if required not in seen:
            raise SystemExit(
                f"corpus gate {level}: {name} must contain {required}, saw {sorted(seen)}"
            )
        if "fneg" in seen:
            raise SystemExit(
                f"corpus gate {level}: {name} must fold the negation into {required}, saw a separate fneg"
            )
    for name in sorted(SQRT_REQUIRED):
        seen = mnemonics.get(name, set())
        if "fsqrt" not in seen:
            raise SystemExit(
                f"corpus gate {level}: {name} must contain fsqrt, saw {sorted(seen)}"
            )
    for name, required_set in UNFUSED_REQUIRED.items():
        seen = mnemonics.get(name, set())
        fused_leak: set[str] = seen & FUSED
        if fused_leak:
            raise SystemExit(
                f"corpus gate {level}: {name} must stay unfused, saw {sorted(fused_leak)}"
            )
        missing: frozenset[str] = required_set - seen
        if missing:
            raise SystemExit(
                f"corpus gate {level}: {name} must contain {sorted(required_set)}, missing {sorted(missing)}"
            )


def main() -> int:
    rows: list[str] = []
    per_level: dict[str, int] = {}
    with tempfile.TemporaryDirectory() as tmp:
        out_dir: Path = Path(tmp)
        for level in LEVELS:
            functions, mnemonics, encodings = disassemble(level, out_dir)
            gate(level, mnemonics)
            gate_fixed_point(level, mnemonics, encodings)
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
