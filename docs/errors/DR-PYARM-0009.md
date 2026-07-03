# DR-PYARM-0009

**AES key extraction failed**

could not recover the AES key from the runtime.

## Common causes

- runtime patched with non-default key derivation
- BCC mode in use

## Common fixes

- try `--allow-dynamic` to capture the runtime in a sandbox

## Source

Emitted from `crates/disrobe-pass-pyarmor/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYARM-0009`.
