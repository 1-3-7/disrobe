# DR-PYARM-0016

**dynamic hook required but not allowed**

static unpack failed & the dynamic-hook fallback was not enabled.

## Common causes

- v6/v7 sample with non-default key derivation

## Common fixes

- re-run with `--allow-dynamic` inside a sandbox

## Source

Emitted from `crates/disrobe-pass-pyarmor/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYARM-0016`.
