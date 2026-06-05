# DR-NUITKA-0007

**nuitka source recovery impossible**

Nuitka emits native machine code; source-level recovery is mathematically impossible.

## Common causes

- asking the wrong tool

## Common fixes

- use `nuitka symbols` for constants/symbols, then a native decompiler for the C++ side

## Source

Emitted from `crates/disrobe-pass-nuitka/src/error.rs`.

Look this up at runtime with `disrobe explain DR-NUITKA-0007`.
