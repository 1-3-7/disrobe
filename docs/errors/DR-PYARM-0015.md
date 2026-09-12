# DR-PYARM-0015

**hex/escape decoding of wrapper bytes failed**

the Python bytes literal contained an escape sequence we cannot decode.

## Common causes

- wrapper post-processed by another obfuscator

## Common fixes

- peel the outer obfuscator with `py deob` first

## Source

Emitted from `crates/disrobe-pass-pyarmor/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYARM-0015`.
