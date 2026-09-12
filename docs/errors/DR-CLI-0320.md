# DR-CLI-0320

**guard denied write to ground-truth stage path**

the candidate path is a committed chain stage output (out/**/stages|final, a .disrobe-stage-lock-marked file, or under an explicit --root) and must not be edited.

## Common causes

- editing a mirrored stage output.bin
- writing inside out/**/final
- path under a .disrobe-stage-lock

## Common fixes

- edit the pass source, not the captured stage artifact
- re-run `disrobe chain` to regenerate stages
- remove the .disrobe-stage-lock if the lock is stale

## Source

Emitted from `crates/disrobe-cli/src/cli/guard.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0320`.
