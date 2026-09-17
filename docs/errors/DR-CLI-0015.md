# DR-CLI-0015

**cannot write pyinstaller entry**

a single TOC entry from the pyinstaller archive could not be written.

## Common causes

- disk full
- filename contained reserved characters on this OS

## Common fixes

- retry to a different `--out` on a filesystem that allows the name

## Source

Emitted from `crates/disrobe-cli/src/cli/pyinstaller.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0015`.
