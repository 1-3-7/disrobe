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

Per-op coverage is measured, not assumed. Op-coverage is scored only when *every* operator in a function is lowered (no `unreachable`/`todo!` stub) and the result validates through an independent re-parser; parseability alone does not count. On the committed corpus **124** of the **126** functions in the 36 parseable modules are fully op-covered: every operator has a lowering rule and the re-emitted WAT re-parses. The MVP instruction set plus the SIMD, atomics, bulk-memory, table/element, reference, and tail-call proposals are lowered. Three corpus modules are skipped on wat-parse or signature-extraction failure, so this is op-coverage of the supported subset, not of all wasm.

Op-coverage is not the same as execution-equivalence. Separately, **50** of the 50 execution-eligible functions (those with a pure-numeric i32/i64/f32/f64 ABI) are execution-equivalent to the original under wasmtime: the `semantic_differential` test compares return values, trap parity, and linear memory between the original and the recovered module, and 6 are byte-identical in memory. The remainder are op-coverage-only. The Component Model envelope, threads, memory64, and the GC type graph are parsed and decoded by dedicated scanners; that is distinct from lifting their per-instruction semantics to source.

## Deobfuscation

```sh
disrobe wasm deob module.wasm --out clean.wasm
```

Reverses four Wasm obfuscator families with byte- or IR-transforming passes: Jscrambler-WASM (strip integrity imports, fold opaque predicates), Wobfuscator (recover the eval op-table and lift each handler), Tigress-via-Emscripten (unflatten the dispatcher, demangle `_Z` names), and Wasmixer (unwrap the XOR decrypt stub, defragment). A fifth family, wasm-name-obfuscator, is detected and its rename strategy classified, but its high-entropy hex renames destroy the original names, so there is nothing to reverse.

## Component Model and GC types

```sh
disrobe wasm component module.wasm        # parse the Component Model envelope -> world / adapter manifest
disrobe wasm types module.wasm            # recover the GC type graph (struct / array / ref types)
```
