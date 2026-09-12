# DR-CLI-0004

**cannot write decrypted plaintext**

post-decryption plaintext could not be written to disk.

## Common causes

- disk full
- permission denied

## Common fixes

- check free space
- retry

## Source

Emitted from `crates/disrobe-cli/src/cli/pyarmor.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0004`.
