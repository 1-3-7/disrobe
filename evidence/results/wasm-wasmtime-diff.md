# WebAssembly recovery, op-coverage and wasmtime execution differential

- id: `wasm-wasmtime-diff`
- ecosystem: wasm
- claim: disrobe lifts WebAssembly to structured source that re-parses with every operator lowered, and the execution-eligible functions execute equivalently to the original under wasmtime.
- measured: 100.00%
- oracle strength: strong
- CI-attested: yes [CI]
- external oracle: wasmtime execution differential (original vs recovered: return values, trap parity, linear memory) for the 50 execution-eligible functions; output re-parse for op-coverage
- reproduce: `cargo test -p disrobe-pass-wasm-deob --test semantic_differential --features sandbox  (op-coverage: cargo test -p disrobe-pass-wasm-deob --test semantic_recovery_corpus)`
- floor: 76.00 (holds)
- gate source: crates/disrobe-pass-wasm-deob/tests/semantic_recovery_corpus.rs measure() = 38 modules parsed / 2 skipped / 133 functions / fully_recovered==133, with the module count and function total pinned by equality and the recovered count floored at 133; tests/semantic_differential.rs = wasmtime execution differential, 57/57 execution-eligible equivalent (6 byte-identical), CI-runnable under --features sandbox; op-coverage is NOT execution-equivalence except for those 57
- note: Op-coverage (124/126) means every operator lowered and the output re-parses; it is NOT execution-equivalence. The 50/50 wasmtime figure is the strong execution-equivalence number. They are distinct and labeled distinctly.
