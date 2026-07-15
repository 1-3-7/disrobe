# disrobe-sleigh

`disrobe-sleigh` preprocesses and parses vendored Ghidra language definitions, compiles constructor patterns into shared decision trees, and lifts selected scalar AArch64, ARMv7 A32/Thumb, MIPS32, RISC-V, and PowerPC instructions into typed P-code.

The runtime uses the Rust standard library only. Test-only `disrobe-core` supplies bounded subprocess execution for GCC, objcopy, and objdump checks. pypcode is used only to regenerate committed semantic reference files. The runtime does not read compiled `.sla` files.

## Decoder API and state

`decode_block` remains the AArch64 compatibility entrypoint. `decode_block_for_language` accepts `Language::AArch64`, `Language::Arm32(ArmMode::A32)`, `Language::Arm32(ArmMode::Thumb)`, `Language::Mips32(Endian)`, `Language::RiscV(RiscVWidth)`, `Language::RiscVCompressed(RiscVWidth)`, `Language::PowerPc32Be`, or `Language::PowerPc64Be`.

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

RISC-V supports RV32 and RV64 register widths. `Language::RiscV` selects the I, M, A, F, D, Zicsr, and Zifencei tables with four-byte instruction alignment. `Language::RiscVCompressed` adds the C table and uses two-byte instruction alignment:

- `addi`, `add`, `sub`, `and`, `or`, `xor`, `sll`, `srl`, `sra`, and `slt`
- `lw`, `sw`, `lui`, and `auipc`, plus RV64 `ld` and `sd`; RV64 `lw` sign-extends its 32-bit load
- `beq`, `bne`, `blt`, `bge`, `jal`, and `jalr`
- `mul`, `mulh`, `mulhsu`, `mulhu`, `div`, `divu`, `rem`, and `remu`
- `flw`, `fsw`, `fld`, and `fsd`; single-precision loads and results are NaN-boxed in the eight-byte floating-point register file
- `fadd`, `fsub`, `fmul`, `fdiv`, `fsqrt`, `feq`, `flt`, and `fle` in single and double precision
- signed integer/float `fcvt.s.w` and `fcvt.w.s`, cross-format `fcvt.d.s` and `fcvt.s.d`, plus `fmv.w.x`, `fmv.x.w`, and RV64 `fmv.d.x` and `fmv.x.d`
- `fmadd.s` and `fmadd.d`
- `csrrw`, `csrrs`, `csrrc`, their three immediate forms, `fence`, and `fence.i`
- the selected `nop` and `ret` constructor aliases
- two-byte `addi`, `li`, `lw`, `sw`, `j`, RV32 `jal`, `jr`, `jalr`, `beqz`, `bnez`, `mv`, `add`, `nop`, `addi4spn`, `lwsp`, and `swsp` encodings, plus RV64 `ld` and `sd` and the matched compressed F/D memory forms
- compressed `sub`, `and`, `or`, and `xor`; the GNU assembly matrices exercise all four, while the `-Os` compiler corpus emits `sub` and `xor`

RISC-V division and remainder are total straight-line P-code. A guarded nonzero divisor reaches `INT_SDIV`, `INT_UDIV`, `INT_SREM`, or `INT_UREM`; mask selection then supplies the specified all-ones quotient or original-dividend remainder for a zero divisor. Signed minimum divided by negative one yields the dividend, and its remainder is zero. No primitive divide receives a zero divisor or the signed-overflow pair.

Floating-point arithmetic emits the matching `FLOAT_ADD`, `FLOAT_SUB`, `FLOAT_MULT`, `FLOAT_DIV`, `FLOAT_SQRT`, comparison, or conversion primitive into a candidate temporary. Versioned `riscv_fp_binary_v1`, `riscv_fp_unary_v1`, `riscv_fp_compare_v1`, and `riscv_fp_convert_v1` contracts produce the architectural result and own RISC-V rounding state, canonical-NaN behavior, and accrued exception flags. Fused multiply-add uses `riscv_fp_fused_v1` directly because a multiply followed by an add would round twice. These arithmetic, comparison, conversion, and fused forms have `DecodeStatus::CallOther`. The listed floating-point loads, stores, and moves are fully supported. Single-precision computational inputs validate the upper 32 bits and substitute canonical quiet NaN for an invalid box; single-precision destinations use `PIECE` with an all-ones upper half. Unsigned integer conversions, RV64 integer conversions, other fused variants, and other matched floating-point constructors remain explicit unsupported `CALLOTHER` output.

`riscv_csr_v1` owns CSR access checks, traps, WARL/WPRI behavior, and side effects. Its optional output is `rd`; its five inputs are the CSR index, source, write/set/clear operation code, read-enabled bit, and write-enabled bit. The enable bits implement the Zicsr zero-register and zero-immediate suppression rules. `riscv_fence_v1` takes fence kind, predecessor mask, successor mask, and mode. Both contracts have `DecodeStatus::CallOther`.

The A extension recognizes `lr.w`, `sc.w`, `amoswap`, `amoadd`, `amoand`, `amoor`, `amoxor`, `amomin`, and `amomax` word forms, plus their doubleword RV64 forms. Every atomic constructor reports `CALLOTHER riscv_atomic_memory_v1`. Its optional output is the destination register; `rd=x0` omits it. Its six inputs are the address, operand, operation code, access width, acquire bit, and release bit. The `lr` operand is zero and ignored. Operation codes 0 through 8 identify `lr`, `sc`, `amoswap`, `amoadd`, `amoand`, `amoor`, `amoxor`, `amomin`, and `amomax` in that order. `lr` and AMO outputs are the prior memory value, with RV64 word results sign-extended to XLEN. The `sc` output is its success or failure status. The call is an opaque memory, reservation, and ordering boundary, so downstream lowering must not replace it with sequential loads and stores.

The base profiles retain four-byte instruction alignment. `jalr` snapshots and masks its target before writing the return address, then emits `BRANCHIND`; `ret` emits `RETURN`. Dynamic base-profile targets keep these effects plus `CALLOTHER riscv_instruction_address_alignment` until indirect-control lowering models the possible misalignment trap. The compressed profiles use two-byte instruction alignment. Their direct branches and `jal` accept targets on either two-byte boundary, and their `jr`, `jalr`, and `ret` effects clear target bit zero and are fully supported.

PowerPC supports PPC32 big-endian scalar forms:

- `add`, `subf`, `and`, `or`, `xor`, `slw`, `srw`, `mullw`, and `divw`
- `addi`, `li`, `lis`, `lwz`, `stw`, `lbz`, and `stb`, including the RA-zero addressing rule
- `cmpw` and `cmpwi` with the selected CR field and XER summary-overflow bit
- direct `b` and `bl`, absolute `ba` and `bla`, fall-through `bl`, `blr`, the exercised unconditional `bclr` with nonzero BH, `bctr`, and conditional branches whose BO and BI fields select CR tests, CTR decrement tests, or both
- the `ori r0,r0,0` `nop` form with its in-spec P-code effect

PowerPC `divw` emits `INT_SDIV`; PPC64 sign-extends its 32-bit word result to the eight-byte destination. The Power ISA leaves the destination undefined for a zero divisor or signed overflow, and the pinned plain Ghidra constructor likewise emits direct signed division, so no result is claimed for those inputs. Record, overflow-enable, and other matched constructors outside this boundary remain explicit unsupported output.

PPC64 big-endian extends the same decoder and BO/BI branch path with:

- eight-byte GPR, address, PC, LR, and CTR operations while CR and XER fields retain their declared widths
- `ld`, `std`, `rldicl`, `rldicr`, `cmpd`, `cmpld`, `mulld`, and `divd`
- the shared arithmetic, logical, word shift, word compare, byte and word memory, immediate, `mullw`, `divw`, and `nop` forms cross-checked at 64-bit register width
- the PPC32 direct, indirect, CR-tested, and CTR-tested branch forms at 64-bit addresses

PowerPC `divd` emits eight-byte `INT_SDIV` with the same undefined-result boundary.

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

The RISC-V corpora are produced by GCC 16.1.0 and GNU Binutils 2.46.1. The PPC32 big-endian corpora are produced by PowerPC EABI GCC 4.9.0 and GNU Binutils 2.24. Each corpus is graded against the objdump from the same installed toolchain:

- RV32IM assembly matrix: 31 of 31 instructions matched a constructor, 29 fully supported, 2 alignment `CALLOTHER` forms (`jalr`, `ret`)
- RV64IM assembly matrix: 33 of 33 instructions matched a constructor, 31 fully supported, 2 alignment `CALLOTHER` forms (`jalr`, `ret`)
- RV32IMAC compressed matrix: 19 of 19 instructions matched a constructor, all 19 fully supported
- RV64IMAC compressed matrix: 20 of 20 instructions matched a constructor, all 20 fully supported
- RV32A atomic matrix: 10 of 10 instructions matched a constructor, all 10 reported through the atomic `CALLOTHER`
- RV64A atomic matrix: 12 of 12 instructions matched a constructor, all 12 reported through the atomic `CALLOTHER`
- RV32FD/Zicsr/Zifencei assembly matrix: 37 of 37 instructions matched a constructor, 7 fully supported, 30 typed `CALLOTHER` forms
- RV64FD/Zicsr/Zifencei assembly matrix: 37 of 37 instructions matched a constructor, 7 fully supported, 30 typed `CALLOTHER` forms
- each `-march=rv32imafdc` or `-march=rv64imafdc` `-O2` C corpus: 21 of 21 instructions matched a constructor, 12 fully supported, 9 typed floating-point `CALLOTHER` forms
- PPC32 big-endian assembly matrix: 32 of 32 instructions matched a constructor, all 32 reported `DecodeStatus::Supported`
- PPC64 big-endian assembly matrix: 30 of 30 instructions matched a constructor, all 30 reported `DecodeStatus::Supported`
- each RISC-V `-O2` C corpus: 11 of 11 instructions matched a constructor, 8 fully supported, 3 alignment `CALLOTHER` forms (`ret`)
- each RISC-V compressed `-Os` C corpus: 11 of 11 instructions matched a constructor, all 11 fully supported
- each RISC-V atomic `-O2` C corpus: 18 of 18 instructions matched a constructor, 12 fully supported, 5 atomic `CALLOTHER` forms, and 1 explicit unsupported `seqz` alias; 6 instructions contain a `CALLOTHER` including that unsupported record
- PPC32 big-endian `-O2` C corpus: 11 of 11 instructions matched a constructor, all 11 reported `DecodeStatus::Supported`

The committed artifacts are always tested. When the cross-toolchains are present, tests compile and grade fresh assembler and C output against the same toolchain's objdump.

`tests/pcode_oracle.rs` also compares 64 AArch64 records and 265 multi-architecture records against pypcode 4.0.0. The multi-architecture set adds 48 F/D primitive-dataflow and memory records plus all eight RV32/RV64 division and remainder records. Single-precision comparisons assume valid NaN-boxed inputs, while separate official-spec vectors exercise valid and invalid boxes. The expected pypcode single-precision register writes are corrected from zero extension to the required all-ones NaN box. Fused operations, CSR and fence side effects, RV64 `fmv.x.w`, and float-to-integer writes are not claimed as pypcode equivalence because the pinned Ghidra translation lacks the required fused primitive, opaque architectural state, or correct transfer effect. Division records compare the primitive operation and original operands; directed boundary vectors and deterministic nonzero identity tests separately grade the total result selection. The atomic comparison ties each encoded register field to the versioned call contract, checks operation, access width, ordering, result, address, and operand facts, and preserves pypcode's detailed reference translation. Base-profile `jalr` and `ret` compare their non-exceptional effects while the alignment marker is asserted separately. The compressed `jr` and `jalr` comparison restores the least-significant-bit clear and uses `BRANCHIND`. The PowerPC `bclr`, `bctr`, and `blr` comparison restores the required low-two-bit target clear that pypcode omits. The normalizers canonicalize independent effects within each control-flow segment while preserving segment order across transfers.

The vendored language files are pinned to Ghidra commit `7462bcec30b597b0b51f549f0bb39a63a942c577`. Each architecture directory contains its Apache License 2.0 files, notice, selected upstream paths, and local scalar-entrypoint changes.

The documented next increment is P-code to NIR-Mir lowering. This crate does not yet depend on or modify the NIR crates.
