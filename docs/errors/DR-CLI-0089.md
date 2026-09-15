# DR-CLI-0089

**envelope migration is unsound**

no transcode path exists, or a Requires capability is unsatisfiable, or a Produces capability is dropped/downgraded.

## Common causes

- incompatible rungs
- capability major-version bump
- dropped output capability

## Common fixes

- register the missing transcode
- align capability majors between source and target

## Source

Emitted from `crates/disrobe-cli/src/cli/envelope.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0089`.
