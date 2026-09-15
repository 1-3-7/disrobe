# DR-PYARM-0018

**dynamic hook timed out**

the watchdog killed the subprocess.

## Common causes

- sample exits slowly
- sample is interactive

## Common fixes

- raise `--dynamic-timeout`

## Source

Emitted from `crates/disrobe-pass-pyarmor/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYARM-0018`.
