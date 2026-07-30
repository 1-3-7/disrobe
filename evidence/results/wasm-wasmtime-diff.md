# WebAssembly recovery, wasmtime execution differential

- id: `wasm-wasmtime-diff`
- ecosystem: wasm
- claim: the execution-eligible functions of the committed WebAssembly corpus execute equivalently to the original under wasmtime after disrobe lifts and re-emits them.
- measured: 100.00%
- oracle strength: strong
- CI-attested: yes [CI]
- external oracle: wasmtime runs the original module and the recovered one on the same inputs and compares return values, trap parity, and the first 4096 bytes of linear memory, for the 57 execution-eligible functions
- reproduce: `cargo test -p disrobe-pass-wasm-deob --test semantic_differential --features sandbox`
- floor: 100.00 (holds)
- gate source: crates/disrobe-pass-wasm-deob/tests/semantic_differential.rs, CI-runnable under --features sandbox; this is the execution-equivalence leg and it is a different, smaller population than the 1034-opcode coverage bar beside it
- note: Execution-eligibility is narrower than op-coverage: a function needs a callable signature and no host imports before it can be run at all, so 57 is a smaller population than the 133-function corpus. The op-coverage figure beside this one is a different and weaker measurement and is graded by its own descriptor, wasm-external-op-inventory.
