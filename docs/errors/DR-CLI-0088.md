# DR-CLI-0088

**cannot read envelope for diff/migrate-check**

one of the two .dr envelopes could not be read or its sidecar failed to decode.

## Common causes

- bad path
- file is not a disrobe envelope
- truncated sidecar

## Common fixes

- verify both paths point at valid .dr envelopes

## Source

Emitted from `crates/disrobe-cli/src/cli/envelope.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0088`.
