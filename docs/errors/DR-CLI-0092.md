# DR-CLI-0092

**stdout write failed**

writing the machine-format result to stdout failed.

## Common causes

- downstream pipe closed
- redirected to read-only path

## Common fixes

- redirect to a writable file

## Source

Emitted from `crates/disrobe-cli/src/cli/output.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0092`.
