# DR-PYARM-0008

**runtime DLL parse failed**

could not parse the PyArmor runtime extension.

## Common causes

- corrupt runtime
- unsupported runtime version

## Common fixes

- ensure the runtime matches the wrapper version

## Source

Emitted from `crates/disrobe-pass-pyarmor/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYARM-0008`.
