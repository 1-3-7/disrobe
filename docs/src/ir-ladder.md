# The five-rung IR ladder

Every artifact **disrobe** recovers climbs the same five-rung intermediate-representation ladder. A pass never jumps arbitrarily; it lifts an artifact from one rung to the next, which is what lets passes from completely different ecosystems compose through a shared envelope.

```text
   Raw  ──>  Disasm  ──>  MIR  ──>  HIR  ──>  Surface
   bytes     opcodes      mid       high      source
```

The rungs are defined once in `disrobe-ir` as `Rung::{Raw, Disasm, Mir, Hir, Surface}` and are the same for Python bytecode, JVM classfiles, .NET CIL, Lua chunks, WebAssembly, and native binaries.

## Rung 1 - Raw

The original bytes, exactly as received, wrapped in an envelope with its detected format and BLAKE3 root recorded. Unpacking and decryption passes (UPX unpack, PyArmor decrypt, PyInstaller extract, container extraction) operate at this rung: they take raw bytes and emit raw bytes that are structurally cleaner but still pre-disassembly. This is where the "byte-identical unpack" guarantee lives - a UPX-unpacked image at the Raw rung is bit-for-bit the original pre-pack image.

## Rung 2 - Disasm

The artifact decoded into a per-instruction listing: CPython opcodes, JVM bytecode, CIL, Lua VM instructions, Wasm operators, or native machine instructions via Capstone/iced-x86/yaxpeax. Disassembly is faithful and lossless - it is a 1:1 decode of the bytes, with offsets preserved. `disrobe py disasm`, `disrobe beam disasm`, `disrobe as3 disasm`, and `disrobe pickle disasm` all stop here deliberately.

## Rung 3 - MIR (mid-level IR)

A normalized, control-flow-aware representation: basic blocks, an explicit CFG, stack effects resolved, super-instructions un-fused, jump targets relocated. This is the rung where decompilers do the structural work that separates a faithful disassembly from readable source. For Python specifically, the **frame-tree pre-pass** runs here: the nested source-construct tree is reconstructed from the 3.11+ exception table *before* the instruction walk, which eliminates the single-pass stack-walker desync that other Python decompilers suffer from.

## Rung 4 - HIR (high-level IR)

Structured control flow recovered: loops, conditionals, try/except/finally, with-blocks, comprehensions, pattern-match arms, generator state machines. Names, types, and idioms are recovered where the source language has them (Kotlin idiom recovery from JVM bytecode, C# vs F# vs VB shapes from CIL). The HIR is language-shaped but not yet rendered as text.

## Rung 5 - Surface

The final rendered source: Python, Java, Kotlin, C#, F#, VB, Rust, TypeScript, WAT, C, Lua, Erlang, or whatever the target dictates. For Python this is where the **round-trip metric** runs: the emitted file is recompiled on the matching interpreter and compared opcode-for-opcode against the original. The verdict is recorded as `PERFECT` (byte-identical), `SEMANTIC` (same program, different layout), or `CODE_DIFF` (a real bug, fixed before ship).

## Why the ladder matters

- **Composition.** Because a pass only declares "I take rung N, I produce rung N+1," the chain runner can stitch passes from different crates without any of them knowing about each other.
- **Honest partial recovery.** If a decompiler can climb to HIR but not cleanly render Surface, it can stop and emit the HIR/Disasm artifact with a `PARTIAL` or `SKELETON` confidence tier rather than fabricating source.
- **Transcoding.** `disrobe-ir` carries a transcode registry keyed on `(from_version, from_rung, to_version, to_rung)`, so an envelope can be migrated across schema versions while staying at the same rung. `disrobe envelope migrate-check` validates that such a path exists and that every required capability stays satisfiable.

## Confidence tiers

Surface output is tagged with one of four tiers, defined in `disrobe-core`:

| Tier | Meaning |
|---|---|
| `exact` | Reserved for byte-roundtrip-verified output. |
| `semantic` | Same program, different but equivalent layout. |
| `partial` | Some bodies recovered, some left as disasm or stubs. |
| `skeleton` | Structure recovered, bodies emitted as `pass`/placeholder. |

These tiers propagate into the `recovery.json` sidecar and the `--llm` bundle, so a downstream consumer always knows how much to trust each recovered symbol.
