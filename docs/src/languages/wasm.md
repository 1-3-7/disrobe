# WebAssembly

`disrobe` parses WebAssembly modules, lifts them to four target surfaces, reverses Wasm-specific obfuscators, and decodes the Component Model and GC type graphs.

## At a glance

| Layer | Coverage |
|---|---|
| Lift targets | Rust, TypeScript, WAT, or C pseudo-source, or a JSON summary |
| Instruction set | MVP plus the SIMD, atomics, bulk-memory, table/element, reference, and tail-call proposals |
| Name recovery | DWARF and source-map names where debug info is present |
| Op-coverage grade | Every operator in the function lowered, and the re-emitted WAT re-parsed by an independent parser |
| Execution grade | Return values, trap parity, and linear memory compared against the original under wasmtime |
| Obfuscators | Jscrambler-WASM, Wobfuscator, Tigress-via-Emscripten, and Wasmixer reversed; wasm-name-obfuscator detected only |
| Envelopes | Component Model, threads, memory64, and the GC type graph parsed by dedicated scanners |

## Commands

```sh
disrobe wasm decompile module.wasm --target rust --out lifted.rs
disrobe wasm decompile module.wasm --target ts   --out lifted.ts
disrobe wasm decompile module.wasm --target wat  --out lifted.wat
disrobe wasm decompile module.wasm --target c    --out lifted.c
disrobe wasm decompile module.wasm --target json --out summary.json
disrobe wasm deob module.wasm --out clean.wasm
disrobe wasm component module.wasm        # parse the Component Model envelope -> world / adapter manifest
disrobe wasm types module.wasm            # recover the GC type graph (struct / array / ref types)
```

`decompile` lifts to Rust, TypeScript, WAT, or C pseudo-source, or a JSON summary, with DWARF / source-map name recovery where debug info is present.

## Coverage and fidelity

Per-op coverage is measured, not assumed. Op-coverage is scored only when *every* operator in a function is lowered (no `unreachable`/`todo!` stub) and the result validates through an independent re-parser; parseability alone does not count. On the committed corpus all **133** of the **133** functions in the 38 parseable modules are fully op-covered: every operator has a lowering rule and the re-emitted WAT re-parses. The MVP instruction set plus the SIMD, atomics, bulk-memory, table/element, reference, and tail-call proposals are lowered.

Op-coverage is not the same as execution-equivalence. Separately, all **57** of the 57 execution-eligible functions (a numeric or nullable-reference ABI the harness can isolate per-function or drive as a whole faithful module) are execution-equivalent to the original under wasmtime: the `semantic_differential` test compares return values, trap parity, and linear memory between the original and the recovered module, and 6 are byte-identical in memory.

`wasm deob` reverses four Wasm obfuscator families with byte- or IR-transforming passes: Jscrambler-WASM (strip integrity imports, fold opaque predicates), Wobfuscator (recover the eval op-table and lift each handler), Tigress-via-Emscripten (unflatten the dispatcher, demangle `_Z` names), and Wasmixer (unwrap the XOR decrypt stub, defragment).

## Limits

- Two corpus modules are skipped on wat-parse or signature-extraction failure, so the op-coverage figure covers the supported subset, not all of wasm.
- Functions outside the execution-eligible set are op-coverage-only; their behavior is not compared against the original.
- The Component Model envelope, threads, memory64, and the GC type graph are parsed and decoded by dedicated scanners. That is distinct from lifting their per-instruction semantics to source.
- A fifth obfuscator family, wasm-name-obfuscator, is detected and its rename strategy classified, but its high-entropy hex renames destroy the original names, so there is nothing to reverse.
