# DR-CLI-0081

**malformed envelope sidecar**

the postcard cold sidecar failed to decode.

## Common causes

- envelope produced by a newer disrobe version
- file truncated

## Common fixes

- upgrade disrobe
- re-emit the envelope

## Source

Emitted from `crates/disrobe-cli/src/cli/envelope.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0081`.
