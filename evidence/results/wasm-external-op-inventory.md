# WebAssembly op-coverage against an external instruction inventory

- id: `wasm-external-op-inventory`
- ecosystem: wasm
- claim: disrobe lowers 1034 of the 1034 opcodes that wasm-tools counts across the 38 parseable modules of the committed corpus, and the WAT it emits re-assembles.
- measured: 100.00%
- oracle strength: coverage-self-reported
- CI-attested: yes [CI]
- evidence basis: the denominator is external and pinned: wasm-tools 1.250.0 disassembles every committed .wat and its per-function instruction inventory is frozen under crates/disrobe-pass-wasm-deob/tests/golden/external_wasm_op_inventory.json, keyed by each fixture's BLAKE3. The numerator is still disrobe counting the opcodes it lowered, so this stays coverage rather than correctness; the emitted WAT is re-assembled by the wat crate before any of its opcodes count
- reproduce: `cargo test -p disrobe-pass-wasm-deob --test external_op_denominator --test semantic_recovery_corpus`
- floor: 100.00 (holds)
- gate source: crates/disrobe-pass-wasm-deob/tests/external_op_denominator.rs divides 1034 lowered opcodes by the 1034 wasm-tools 1.250.0 counts over the same modules, and pins each fixture's hash so a changed corpus fails rather than re-scores; crates/disrobe-pass-wasm-deob/tests/semantic_recovery_corpus.rs measure() = 38 modules parsed / 2 skipped / 133 functions / fully_recovered==133, with the module count and function total pinned by equality and the recovered count floored at 133; tests/semantic_differential.rs = wasmtime execution differential, 57/57 execution-eligible equivalent (6 byte-identical), CI-runnable under --features sandbox; op-coverage is NOT execution-equivalence except for those 57
- note: The tier is coverage-self-reported because a lowering rule firing is not the same as the lowering being right. What the external leg removes is the older defect where both sides of the ratio came from disrobe's own parser, which could not report its own regression: the denominator now stays at 1034 while a decoder that stops seeing opcodes drives the numerator down. Instruction-for-instruction the two decoders agree, 1034 accounted against 1034 counted, with 0 unseen. Semantic grading for this corpus lives in wasm-wasmtime-diff, which covers the 57 execution-eligible functions. The inventory is committed rather than regenerated in CI so no missing tool can turn into a pass; regenerating it demands wasm-tools 1.250.0 and fails without it.
