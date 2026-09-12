# DR-CLI-0012

**cannot read pyinstaller archive for extract**

`pyinstaller extract` could not load the binary into memory.

## Common causes

- file does not exist
- permission denied

## Common fixes

- verify path
- fix permissions

## Source

Emitted from `crates/disrobe-cli/src/cli/pyinstaller.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0012`.
