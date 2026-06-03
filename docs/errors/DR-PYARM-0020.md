# DR-PYARM-0020

**dynamic hook produced zero captures**

the subprocess ran but no marshal streams were captured.

## Common causes

- sample exited before reaching protected code
- anti-debug check tripped

## Common fixes

- increase timeout, retry on a different host

## Source

Emitted from `crates/disrobe-pass-pyarmor/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYARM-0020`.
