# DR-NUITKA-0007

**nuitka source text not present**

Nuitka emits native code, so the original Python source text is not present in the artifact; constants and symbols are, and where the build .c is shipped, body recovery is partial.

## Common causes

- asking the wrong tool

## Common fixes

- use `nuitka symbols` for constants/symbols, then a native decompiler for the C++ side

## Source

Emitted from `crates/disrobe-pass-nuitka/src/error.rs`.

Look this up at runtime with `disrobe explain DR-NUITKA-0007`.
