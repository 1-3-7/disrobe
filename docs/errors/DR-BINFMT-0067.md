# DR-BINFMT-0067

**cython extension recovery failed**

the compiled Cython extension could not be recovered.

## Common causes

- not a Cython-built extension
- truncated shared object

## Common fixes

- confirm the input is a Cython-compiled .pyd or .so extension

## Source

Emitted from `crates/disrobe-binfmt/src/error.rs`.

Look this up at runtime with `disrobe explain DR-BINFMT-0067`.
