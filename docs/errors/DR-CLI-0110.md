# DR-CLI-0110

**init: target .disrobe already exists**

`disrobe init` refuses to overwrite an existing scaffold without `--force`.

## Common causes

- re-running init in an initialized project

## Common fixes

- pass `--force` to overwrite, or remove `.disrobe/` first

## Source

Emitted from `crates/disrobe-cli/src/cli/init.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0110`.
