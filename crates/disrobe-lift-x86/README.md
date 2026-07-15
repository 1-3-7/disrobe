# disrobe-lift-x86

`disrobe-lift-x86` decodes bounded x86-64 byte streams with iced-x86 and emits the P-code types shared with `disrobe-sleigh`.

```rust
use disrobe_lift_x86::decode_block_x86;

let block = decode_block_x86(&[0x48, 0x01, 0xd0], 0x401000, 64);
assert_eq!(block.consumed, 3);
```

The modeled set covers register, immediate, and ModRM memory forms of `mov`; register or memory source forms of `movzx` and `movsx`; `lea`; 64-bit `push`, `pop`, and `leave`; register `xchg`; scalar integer arithmetic and logic with register or memory destinations; nonzero immediate shifts whose counts do not exceed the operand width; one-, two-, and three-operand multiplication; direct and indirect control flow; conditional branches; `call`; `ret`; `nop`; and `endbr64`. Division uses a checked typed `CALLOTHER` contract because divide-by-zero and quotient overflow require exceptional control flow that the shared P-code enum cannot express directly.

Every successfully decoded instruction produces a `PcodeInstr`. Instructions outside the modeled set use a versioned `CALLOTHER` name ending in `pure_v1`, `reads_mem_v1`, `writes_mem_v1`, or `side_effecting_v1`. Locked operations, memory `xchg`, system operations, and fences are side-effecting. Malformed input, unsupported bitness, and configured limits produce explicit status records.

The default limits are 1 MiB and 65,536 instructions. `X86PcodeLifter::with_limits` can lower either bound. Only 64-bit decoding is accepted.

The general-purpose, instruction-pointer, and flag offsets exercised by the effect corpus match the Ghidra `x86:LE:64:default` register space. Segment, vector, and mask offsets are isolated in the same mapping table for address terms and opaque contracts but are outside the corpus agreement numerator. State without a mapped offset remains inside a side-effecting opaque contract instead of receiving an invented register offset. The shared `Varnode` type records byte widths, so CF, PF, AF, ZF, SF, and OF are represented as one-byte boolean varnodes rather than bit-width varnodes.

The committed GCC oracle corpus contains 95 instructions. GNU objdump agrees with all 95 boundaries and mnemonics. The lifter fully models 92 and emits typed `CALLOTHER` records for 3. The normalized architectural effects of all 92 modeled instructions agree with pypcode 4.0.0. The checked pypcode verifier regenerates the raw translation and normalized table byte-for-byte. See `tests/corpus/PROVENANCE.md` for tools, hashes, commands, and normalization rules.

The next instruction-coverage increment should add dynamic-count shifts, rotates, conditional moves, sign-extension helpers, more multiply and divide forms, string operations, atomics, fences, and selected SIMD families. The planned shared P-code to NIR-Mir lowering should then accept x86-64 and Sleigh-backed architectures through the same middle end.
