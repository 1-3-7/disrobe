# DR-PYARM-0017

**no usable Python found for dynamic hook**

no Python >= 3.9.7 was located on PATH.

## Common causes

- python not installed
- pyenv shim points elsewhere

## Common fixes

- install Python 3.9.7+
- set DISROBE_PYTHON to a usable interpreter

## Source

Emitted from `crates/disrobe-pass-pyarmor/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYARM-0017`.
