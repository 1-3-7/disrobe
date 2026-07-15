# disrobe-lift-x86

`disrobe-lift-x86` decodes bounded x86-64 byte streams with iced-x86 and emits the P-code types shared with `disrobe-sleigh`.

```rust
use disrobe_lift_x86::decode_block_x86;

let block = decode_block_x86(&[0x48, 0x01, 0xd0], 0x401000, 64);
assert_eq!(block.consumed, 3);
```

The modeled set covers register, immediate, and ModRM memory forms of `mov`; register or memory source forms of `movzx`, `movsx`, and `movsxd`; `lea`; 64-bit `push`, `pop`, and `leave`; register `xchg`; scalar integer arithmetic and logic with register or memory destinations; nonzero immediate shifts whose counts do not exceed the operand width; CL-controlled `shl`, `shr`, `sar`, `shld`, and `shrd` with register or memory destinations and the masked-count and conditional-flag semantics; one-, two-, and three-operand multiplication; all 16 `setcc` and `cmovcc` conditions; register and memory `bt`, `bts`, `btr`, and `btc`; `bswap`; `xadd`; the accumulator sign-extension family; immediate `shld` and `shrd`; direct and indirect control flow; conditional branches; `call`; `ret`; `nop`; and `endbr64`.

Modeled SSE state covers `movss`, scalar `movsd`, `movaps`, `movups`, XMM `movd` and `movq`, `pxor`, `xorps`, `xorpd`, `andps`, and `orps`. XMM0 through XMM15 use 16-byte register varnodes with scalar lane slices. Register and memory `movaps` and `movups` share the same lane transfer because the Ghidra `x86:LE:64:default` translation does not distinguish their alignment fault in the effect record. Unprefixed `movs`, `stos`, `lods`, `cmps`, and `scas` iterations emit their memory effect, direction-flag-selected pointer updates, accumulator effect, and comparison flags.

Division uses a checked typed `CALLOTHER` contract because divide-by-zero and quotient overflow require exceptional control flow that the shared P-code enum cannot express directly. Bit scans and counts, MXCSR-sensitive scalar floating-point operations and conversions, REP string loops, locked operations, memory exchanges, compare-exchanges, and fences also use named typed contracts. These contracts expose explicit register, pointer, flag, MXCSR, count, direction, width, and ordering inputs and outputs plus conservative memory and ordering effect summaries. They do not claim straight-line semantics that the shared P-code container cannot express.

Every successfully decoded instruction produces a `PcodeInstr`. Instructions outside the modeled set use a versioned `CALLOTHER` name ending in `pure_v1`, `reads_mem_v1`, `writes_mem_v1`, `reads_writes_mem_v1`, or `side_effecting_v1`. Locked operations, memory `xchg`, system operations, and fences are side-effecting. Malformed input, unsupported bitness, and configured limits produce explicit status records.

The default limits are 1 MiB and 65,536 instructions. `X86PcodeLifter::with_limits` can lower either bound. Only 64-bit decoding is accepted.

The general-purpose, instruction-pointer, flag, and XMM offsets exercised by the P-code effects corpus match the Ghidra `x86:LE:64:default` register space. Segment and mask offsets are isolated in the same mapping table for address terms and typed contracts. State without a mapped offset remains inside a side-effecting contract instead of receiving an invented register offset. The shared `Varnode` type records byte widths, so CF, PF, AF, ZF, SF, DF, and OF are represented as one-byte boolean varnodes rather than bit-width varnodes.

The committed GCC corpus contains 281 instructions. GNU objdump agrees with all 281 boundaries and mnemonics. The lifter fully models 223 and emits typed `CALLOTHER` records for 58. The added fixture region contains 186 instructions: 130 modeled and 56 typed-contract records. The normalized architectural effects of all 223 modeled instructions agree with pypcode 4.0.0. The checked pypcode verifier regenerates the raw translation and normalized table byte-for-byte. See `tests/corpus/PROVENANCE.md` for tools, hashes, commands, and normalization rules.

The next instruction-coverage increment should replace the remaining bit-scan and count, scalar floating-point, REP-loop, and atomic contracts only where the shared representation gains the needed bit-scan and population-count operations, local-control-flow, MXCSR, and memory-ordering primitives. The bit-scan and count forms keep typed contracts because Ghidra models them with a population-count operation and internal branch that the shared enum does not carry. Packed SSE lane arithmetic and more vector moves remain outside the modeled set. The planned shared P-code to NIR-Mir lowering should then accept x86-64 and Sleigh-backed architectures through the same middle end.
