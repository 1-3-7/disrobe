# DR-PYDEOB-0008

**py-deob invalid utf-8 in output**

the deobfuscated bytes were not valid UTF-8 python source.

## Common causes

- wrong layer detected

## Common fixes

- report sample

## Source

Emitted from `crates/disrobe-pass-py-deob/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYDEOB-0008`.
