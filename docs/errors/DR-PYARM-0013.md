# DR-PYARM-0013

**PyArmor v3/v4/v5 capsule walled on the RSA-wrapped key**

v3-v5 capsule structure and metadata parse, but the bytecode AES key is RSA-wrapped with a private key the author never ships, so the plaintext is not in the artifact and cannot be recovered statically.

## Common causes

- a v3-v5 capsule whose per-script AES key is sealed with the project private RSA key

## Common fixes

- supply the cleartext capsule key if you hold it; structure, version, and metadata still parse without it

## Source

Emitted from `crates/disrobe-pass-pyarmor/src/error.rs`.

Look this up at runtime with `disrobe explain DR-PYARM-0013`.
