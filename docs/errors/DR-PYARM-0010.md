# DR-PYARM-0010

**AES decryption failed**

the recovered key did not yield valid marshal output.

## Common causes

- wrong key extracted
- wrong IV

## Common fixes

- try the dynamic hook fallback

## Source

Emitted from `crates/disrobe-pass-pyarmor/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYARM-0010`.
