# DR-CLI-0003

**cannot write pyarmor manifest**

could not write `manifest.json` into the output dir.

## Common causes

- disk full
- permission revoked mid-run

## Common fixes

- free disk space
- retry with a different `--out`

## Source

Emitted from `crates/disrobe-cli/src/cli/pyarmor.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0003`.
