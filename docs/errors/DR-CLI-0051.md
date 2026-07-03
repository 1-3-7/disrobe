# DR-CLI-0051

**input is not a valid pyc**

the marshal header did not parse.

## Common causes

- file is not a .pyc
- corrupt header
- unknown python magic

## Common fixes

- confirm input via `file`
- regenerate with the matching python version

## Source

Emitted from `crates/disrobe-cli/src/cli/py.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0051`.
