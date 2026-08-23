# DR-WASMDEOB-0005

**WebAssembly lifting input limit**

the module exceeds the configured lifting input limit.

## Common causes

- a large module
- a small consumer lifting limit

## Common fixes

- use a smaller module
- raise the lifting limit when memory permits

## Source

Emitted from `crates/disrobe-pass-wasm-deob/src/error.rs`.

Look this up at runtime with `disrobe explain DR-WASMDEOB-0005`.
