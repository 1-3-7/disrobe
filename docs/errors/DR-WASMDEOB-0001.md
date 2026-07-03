# DR-WASMDEOB-0001

**not a valid WebAssembly module**

wasmparser rejected the binary.

## Common causes

- wrong file
- truncated module

## Common fixes

- validate with `wasm-validate`

## Source

Emitted from `crates/disrobe-pass-wasm-deob/src/error.rs`.

Look this up at runtime with `disrobe explain DR-WASMDEOB-0001`.
