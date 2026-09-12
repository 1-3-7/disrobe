# DR-PYDEOB-0003

**py-deob depth limit reached**

encoder peel hit the depth cap without converging.

## Common causes

- very deeply nested encoder
- non-terminating obfuscator

## Common fixes

- report sample for investigation

## Source

Emitted from `crates/disrobe-pass-py-deob/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYDEOB-0003`.
