# WebAssembly

**disrobe** parses WebAssembly modules and lifts them to four target surfaces, reverses Wasm-specific obfuscators, and decodes the Component Model and GC type graphs.

## Decompilation

```sh
disrobe wasm decompile module.wasm --target rust --out lifted.rs
disrobe wasm decompile module.wasm --target ts   --out lifted.ts
disrobe wasm decompile module.wasm --target wat  --out lifted.wat
disrobe wasm decompile module.wasm --target c    --out lifted.c
disrobe wasm decompile module.wasm --target json --out summary.json
```

Lifts to Rust, TypeScript, WAT, or C pseudo-source, or a JSON summary, with DWARF / source-map name recovery where debug info is present.

Honest per-op coverage is tracked and measured, not assumed. Recovery is scored only when *every* operator in a function is genuinely lowered (no `unreachable`/`todo!` stub) and the result validates through an independent re-parser - parseability alone does not count. On the committed corpus the measured semantic recovery is **58/76 = 76.3%** of defined function bodies: the MVP instruction set plus the SIMD, atomics, bulk-memory, table/element, reference, and tail-call proposals are genuinely lowered. Exceptions and GC (struct/array/i31) are detected and scanned but not yet lifted to validating source - they are reported as untranslated rather than silently stubbed. The Component Model envelope, threads, memory64, and the GC type graph are parsed and decoded by dedicated scanners; that is distinct from lifting their per-instruction semantics to source.

## Deobfuscation

```sh
disrobe wasm deob module.wasm --out clean.wasm
```

Reverses five Wasm obfuscator families: wasm-name-obfuscator, Jscrambler-WASM, Wobfuscator, Tigress-via-Emscripten, and Wasmixer.

## Component Model and GC types

```sh
disrobe wasm component module.wasm        # parse the Component Model envelope -> world / adapter manifest
disrobe wasm gc-types module.wasm         # recover the GC type graph (struct / array / ref types)
```
