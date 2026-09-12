# DR-CLI-0011

**cannot read pyinstaller input**

`pyinstaller detect|extract` could not read the binary path.

## Common causes

- file does not exist
- permission denied

## Common fixes

- verify path
- fix permissions

## Source

Emitted from `crates/disrobe-cli/src/cli/pyinstaller.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0011`.
