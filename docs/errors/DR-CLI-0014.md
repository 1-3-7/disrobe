# DR-CLI-0014

**cannot write pyinstaller manifest**

`manifest.json` write failed inside the pyinstaller output dir.

## Common causes

- disk full
- permission denied

## Common fixes

- free space
- retry

## Source

Emitted from `crates/disrobe-cli/src/cli/pyinstaller.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0014`.
