# DR-CLI-0002

**cannot create pyarmor output directory**

the `--out` path could not be created on disk.

## Common causes

- permission denied on parent dir
- path crosses a read-only mount

## Common fixes

- pick a writable `--out` location
- create the parent directory first

## Source

Emitted from `crates/disrobe-cli/src/cli/pyarmor.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0002`.
