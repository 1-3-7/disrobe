# DR-CLI-0042

**non utf-8 source / write failed**

either the JS source was not valid UTF-8, or the wasm summary.json write failed (two passes reuse this code).

## Common causes

- binary file passed as JS source
- disk full on wasm output

## Common fixes

- check input charset
- free space

## Source

Emitted from `crates/disrobe-cli/src/cli/{js,wasm}.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0042`.
