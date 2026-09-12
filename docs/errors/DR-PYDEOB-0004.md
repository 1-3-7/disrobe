# DR-PYDEOB-0004

**py-deob base64 decode failed**

an intermediate base64 layer did not decode.

## Common causes

- custom alphabet
- corrupted source

## Common fixes

- re-fetch the sample

## Source

Emitted from `crates/disrobe-pass-py-deob/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYDEOB-0004`.
