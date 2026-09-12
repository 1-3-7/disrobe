# DR-PYARM-0006

**PyArmor v8/v9 magic mismatch**

expected `PY` + 6 digits magic was not present.

## Common causes

- sample is not v8/v9

## Common fixes

- try the v6/v7 path

## Source

Emitted from `crates/disrobe-pass-pyarmor/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYARM-0006`.
