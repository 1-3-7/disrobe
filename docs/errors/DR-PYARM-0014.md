# DR-PYARM-0014

**BCC mode is partial-only**

BCC payloads require a native lifter; only the Python half is recoverable today.

## Common causes

- sample built with PyArmor BCC mode

## Common fixes

- accept partial recovery
- use `nuitka symbols`-style approach for the native side

## Source

Emitted from `crates/disrobe-pass-pyarmor/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYARM-0014`.
