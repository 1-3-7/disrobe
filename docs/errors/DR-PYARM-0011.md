# DR-PYARM-0011

**marshal decode error after decrypt**

the decrypted bytes did not parse as Python marshal.

## Common causes

- wrong decrypted payload
- outer layer not stripped

## Common fixes

- re-run with `RUST_LOG=debug` & report the marshal offset

## Source

Emitted from `crates/disrobe-pass-pyarmor/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYARM-0011`.
