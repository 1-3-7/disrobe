# disrobe-sleigh

`disrobe-sleigh` is a source-level Sleigh front end and scalar AArch64 instruction lifter. It preprocesses and parses the vendored Ghidra language definitions, compiles constructor patterns into a decision tree, and emits typed P-code operations from raw instruction bytes.

The runtime crate uses the Rust standard library only. Its test-only `disrobe-core` dependency supplies bounded subprocess execution for the external GCC, objcopy, and objdump checks. Pypcode is required only when regenerating the committed semantic reference files. The runtime never reads a compiled `.sla`; pypcode is an external test oracle only.

The first increment supports these scalar forms:

- `add`, `adds`, `sub`, `subs`, `cmp`, and `cmn` with an immediate or shifted register
- `and`, `ands`, `tst`, `orr`, `eor`, and register `mov` aliases with `lsl`, `lsr`, or `asr` shifts
- `movz`, `movn`, `movk`, and move-wide `mov` aliases
- `lsl`, `lsr`, and `asr` bitfield aliases
- 32-bit and 64-bit unsigned-offset `ldr` and `str`
- 32-bit and 64-bit offset, pre-indexed, and post-indexed `ldp` and `stp`
- 32-bit and 64-bit `mul`, `madd`, `msub`, and `csel`
- `b`, `bl`, `b.cond`, `cbz`, `cbnz`, `br`, `blr`, `ret`, `adr`, `adrp`, and `nop`

A matched constructor outside that list emits `CALLOTHER` with the source-defined pcodeop name when one is present. For example, `svc` emits `CALLOTHER CallSupervisor`. Other matched constructors emit an explicit unsupported status and a mnemonic-specific `CALLOTHER`. Truncated, ambiguous, and unmatched bytes remain separate decode states. General bitfield forms, logical immediates, sign-extending and non-unsigned-offset memory forms, atomics, exclusive operations, system instructions, pointer authentication, and scalar divide are not lifted in this increment.

The public compiler defaults to strict conflict handling: equal or partially overlapping patterns decode as ambiguous unless one pattern is proven to be a proper subset of every other match. `ConflictPolicy::FirstDefined` implements Sleigh's documented lenient rule for specifications that intentionally retain partial intersections. The vendored Ghidra AArch64 language requires that explicit policy for documented aliases such as immediate `asr`.

The vendored files under `vendor/aarch64` come from Ghidra commit `7462bcec30b597b0b51f549f0bb39a63a942c577`. `vendor/aarch64/ATTRIBUTION.md` records the selected files, source hashes, and the two include removals that keep this increment scalar-only. The upstream Apache License 2.0 and notice are preserved alongside the specifications.

`tests/compiler_oracle.rs` compiles `tests/fixtures/aarch64_oracle.c` with an external AArch64 GNU/Linux GCC at `-O0` and `-O2`, extracts `.text`, compares every decoded mnemonic with GNU objdump, and checks coverage and fallback ratios. The current compiler fixture measures 93 of 93 instruction instances at `-O0` and 46 of 46 at `-O2`, with no `CALLOTHER` or unsupported instructions. The combined reference stream contains `add`, `and`, `asr`, `b`, `b.ne`, `bl`, `cmp`, `csel`, `eor`, `ldp`, `ldr`, `lsl`, `lsr`, `madd`, `mov`, `mul`, `nop`, `orr`, `ret`, `stp`, `str`, and `sub`. A separate 64-instruction assembly matrix exercises every supported family and both register widths where applicable. It also reaches 100 percent decode coverage with exact GNU objdump mnemonic agreement. The committed compiler artifacts are pinned to Arm GNU Toolchain 15.2. When another cross-toolchain is installed, its fresh output is graded against its own objdump rather than required to match the pinned code generation.

`tests/pcode_oracle.rs` checks the architectural effects of all 64 assembly-matrix instructions against pypcode 4.0.0 using Ghidra's `AARCH64:LE:64:v8A` language. The comparison preserves register offsets and widths, final register values, flags, RAM access widths and addresses, pair writeback, branch targets, and call/link behavior. The raw external translations, normalized facts, pinned dependency, generator, commands, and hashes are committed under `tests/corpus` and `tests/fixtures`.

Lowering this P-code IR into a Mir rung is explicitly deferred to the next increment. This crate does not depend on or modify the NIR crates.
