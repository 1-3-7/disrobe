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

Lifts to Rust, TypeScript, WAT, or C pseudo-source, or a JSON summary. The lifter handles the modern proposals: GC, the Component Model, threads, SIMD, tail-call, and memory64, with DWARF recovery where debug info is present.

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
