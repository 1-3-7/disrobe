# DR-CLI-0140

**completions install: cannot locate shell config**

could not figure out which rc file to update for the requested shell.

## Common causes

- uncommon shell layout
- missing HOME / PROFILE env

## Common fixes

- pass `--rc-file` to point at your rc explicitly

## Source

Emitted from `crates/disrobe-cli/src/cli/completions.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0140`.
