# DR-PYARM-0007

**PyArmor v6/v7 magic mismatch**

expected `PYARMOR\0` magic was not present.

## Common causes

- sample is not v6/v7

## Common fixes

- try the v8/v9 path
- verify with `pyarmor inspect`

## Source

Emitted from `crates/disrobe-pass-pyarmor/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYARM-0007`.
