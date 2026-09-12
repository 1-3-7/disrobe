# DR-CLI-0087

**envelope verification failed**

BLAKE3 root hash did not match the envelope payload.

## Common causes

- tampered envelope
- truncated file

## Common fixes

- re-fetch the envelope
- regenerate

## Source

Emitted from `crates/disrobe-cli/src/cli/envelope.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0087`.
