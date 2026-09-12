# DR-PYARM-0004

**PyArmor runtime extension not found**

no pyarmor runtime DLL/SO was located next to the wrapper.

## Common causes

- sample shipped without runtime
- runtime is at a custom path

## Common fixes

- place the runtime DLL/SO in the same dir as the wrapper

## Source

Emitted from `crates/disrobe-pass-pyarmor/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYARM-0004`.
