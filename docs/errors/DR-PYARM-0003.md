# DR-PYARM-0003

**payload bytes literal missing**

the embedded `b'...'` payload could not be located in the wrapper.

## Common causes

- custom wrapper layout
- wrapper has been further obfuscated

## Common fixes

- run `py deob` first to peel the outer encoder

## Source

Emitted from `crates/disrobe-pass-pyarmor/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYARM-0003`.
