# DR-PYARM-0019

**dynamic hook subprocess error**

the dynamic-hook subprocess exited with a non-zero status.

## Common causes

- sample raised during import
- missing Python deps

## Common fixes

- check the captured stderr in the output dir

## Source

Emitted from `crates/disrobe-pass-pyarmor/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYARM-0019`.
