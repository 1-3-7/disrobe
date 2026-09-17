# DR-MARSHAL-0010

**long-int digit count too large**

long-int field would allocate beyond the sanity cap.

## Common causes

- pathological input

## Common fixes

- refuse the sample

## Source

Emitted from `crates/disrobe-py-marshal/src/error.rs`.

Look this up at runtime with `disrobe explain DR-MARSHAL-0010`.
