# disrobe-sleigh

`disrobe-sleigh` preprocesses and parses vendored Ghidra language definitions, compiles constructor patterns into shared decision trees, and lifts selected scalar AArch64, ARMv7 A32/Thumb, and MIPS32 instructions into typed P-code.

The runtime uses the Rust standard library only. Test-only `disrobe-core` supplies bounded subprocess execution for GCC, objcopy, and objdump checks. Pypcode is used only to regenerate committed semantic reference files. The runtime does not read compiled `.sla` files.

## Decoder API and state

`decode_block` remains the AArch64 compatibility entrypoint. `decode_block_for_language` accepts `Language::AArch64`, `Language::Arm32(ArmMode::A32)`, `Language::Arm32(ArmMode::Thumb)`, or `Language::Mips32(Endian)`.

ARM mode seeds the real Ghidra `TMode` context field before constructor selection. A32 and Thumb therefore share the same parsed specification and decision engine while using the correct 32-bit or variable 16/32-bit token sequence. Dynamic mode-changing targets remain control-flow boundaries; the caller supplies the target mode when decoding the destination.

`DecodedBlock.instructions` retains physical address order. `DecodedBlock.ordered_ops` retains execution order. For a MIPS transfer with `delayslot(1)`, the scheduler emits branch setup, the following delay-slot instruction's P-code, and then the transfer. A missing delay-slot instruction or a transfer nested in the delay slot is explicit unsupported output and never a successful transfer with omitted effects.

Compilation rejects any constructor table above 2,048 entries. Each decode also stops after 65,536 constructor attempts and returns an explicit resource-limit outcome.

## Supported lifting boundary

AArch64 supports:

- `add`, `adds`, `sub`, `subs`, `cmp`, and `cmn` with an immediate or shifted register
- `and`, `ands`, `tst`, `orr`, `eor`, and register `mov` aliases with `lsl`, `lsr`, or `asr`
- `movz`, `movn`, `movk`, move-wide aliases, and bitfield shift aliases
- scalar `ldr`, `str`, `ldp`, `stp`, `mul`, `madd`, `msub`, and `csel` forms exercised by the committed corpus
- direct, conditional, register-indirect, call, return, address, and `nop` forms exercised by the committed corpus

ARMv7 supports these A32 forms:

- `add`, `sub`, `rsb`, `and`, `eor`, `orr`, `mov`, and `cmp` with supported immediate or immediate-shifted operands
- `movw`, `movt`, `mul`, and `mla`
- word `ldr` and `str` with immediate offset, pre-index, post-index, and writeback
- `ldm`, `stm`, `push`, and `pop`
- direct and conditional `b`, plus unconditional `bl` and `bx`

ARMv7 supports these Thumb forms:

- narrow arithmetic, logical, multiply, compare, move, and immediate-shift forms used by the form and compiler corpora
- high-register `add`, `mov`, `cmp`, and `bx`
- `movw`, `movt`, narrow word `ldr`/`str`, and the exercised wide post-indexed word memory form
- `ldmia`, `stmia`, `push`, and `pop`
- direct and conditional `b`, `cbz`, `cbnz`, unconditional `bl` and `bx`, and `nop`

MIPS32 big-endian and little-endian support:

- `addu`, `subu`, `addiu`, `and`, `or`, `xor`, `slt`, `sltu`, `slti`, `sltiu`, `andi`, `ori`, and `xori`
- immediate `sll`, `srl`, and `sra`, plus the `move` and `li` aliases exercised by GCC
- `lw`, `sw`, and `lui`
- `beq`, `bne`, common zero-register aliases, `j`, `jal`, `jr`, and `jalr` with one delay slot
- `mult`, `multu`, and `nop`

MIPS trapping `add` and `sub` emit the arithmetic effect plus `CALLOTHER mips_overflow_trap`. `div` and `divu` emit quotient and remainder effects plus `CALLOTHER mips_division_edge_cases` because divide-by-zero and signed overflow behavior cannot be represented by the current straight-line P-code container. These forms are reported separately from fully supported forms.

A matched constructor outside the listed boundary emits a source pcodeop `CALLOTHER` when available or a mnemonic-specific unsupported `CALLOTHER`. Truncated, ambiguous, unmatched, and specification-error states remain distinct.

## External grading

The AArch64 compiler corpora contain 93 instructions at `-O0`, 46 at `-O2`, and a 64-instruction assembly matrix. Each reaches a 100 percent constructor-match rate with exact GNU objdump mnemonic agreement and no unsupported or `CALLOTHER` forms.

The ARM32 and MIPS corpora are produced by real Android NDK r16b GNU cross-toolchains and graded against their matching GNU objdump binaries:

- A32 assembly matrix: 20 of 20 instructions matched a constructor, 20 fully supported, 0 `CALLOTHER`
- Thumb assembly matrix: 23 of 23 instructions matched a constructor, 23 fully supported, 0 `CALLOTHER`
- MIPS32 little-endian assembly matrix: 28 of 28 instructions matched a constructor, 25 fully supported, 3 `CALLOTHER`
- MIPS32 big-endian assembly matrix: 28 of 28 instructions matched a constructor, 25 fully supported, 3 `CALLOTHER`
- A32 `-O2` C corpus: 19 of 19 instructions matched a constructor, 19 fully supported
- Thumb `-O2` C corpus: 22 of 22 instructions matched a constructor, 22 fully supported
- each MIPS32 `-O2` C corpus: 20 of 20 instructions matched a constructor, 20 fully supported

The committed artifacts are always tested. When the cross-toolchains are present, tests compile and grade fresh assembler and C output against the same toolchain's objdump.

`tests/pcode_oracle.rs` also compares 64 AArch64 records and 31 multi-architecture records against pypcode 4.0.0. The multi-architecture records use Ghidra languages `ARM:LE:32:v7`, `ARM:LE:32:v8T`, `MIPS:LE:32:default`, and `MIPS:BE:32:default`. They cover final register values, flags, RAM effects, calls/link writes, ARM branch exchange and stack returns, Thumb PC reads and writes, and a MIPS conditional transfer whose delay-slot write must precede the transfer. The normalizers canonicalize independent effects within each control-flow segment while preserving segment order across transfers.

The vendored language files are pinned to Ghidra commit `7462bcec30b597b0b51f549f0bb39a63a942c577`. Each architecture directory contains its Apache License 2.0 files, notice, selected upstream paths, and local scalar-entrypoint changes.

The documented next increment is P-code to NIR-Mir lowering. This crate does not yet depend on or modify the NIR crates.
