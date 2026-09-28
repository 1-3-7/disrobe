# DR-WASMDEOB-0006

**WebAssembly recovery produced an invalid module**

a recovery rewrite emitted a module that fails validation, so the result is withheld.

## Common causes

- a rewrite pattern that does not hold for this module

## Common fixes

- report the input; `disrobe wasm decompile` still reads the original module

## Source

Emitted from `crates/disrobe-pass-wasm-deob/src/error.rs`.

Look this up at runtime with `disrobe explain DR-WASMDEOB-0006`.
