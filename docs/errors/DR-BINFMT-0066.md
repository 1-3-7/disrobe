# DR-BINFMT-0066

**.NET single-file bundle parse failed**

the .NET single-file bundle manifest did not parse.

## Common causes

- truncated bundle
- unsupported bundle version

## Common fixes

- confirm the input is a .NET single-file bundle (major version 1, 2, or 6 and up)

## Source

Emitted from `crates/disrobe-binfmt/src/error.rs`.

Look this up at runtime with `disrobe explain DR-BINFMT-0066`.
