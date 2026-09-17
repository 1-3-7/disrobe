# DR-WASMDEOB-0004

**WebAssembly source output limit**

the lifted source would exceed the configured output limit.

## Common causes

- a large module
- a small consumer output limit

## Common fixes

- use a smaller module
- raise the output limit when memory permits

## Source

Emitted from `crates/disrobe-pass-wasm-deob/src/error.rs`.

Look this up at runtime with `disrobe explain DR-WASMDEOB-0004`.
