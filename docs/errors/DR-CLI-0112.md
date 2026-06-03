# DR-CLI-0112

**init: cannot write scaffold file**

writing one of the scaffold files failed mid-run.

## Common causes

- disk full
- permission revoked

## Common fixes

- retry, then `disrobe init --force`

## Source

Emitted from `crates/disrobe-cli/src/cli/init.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0112`.
