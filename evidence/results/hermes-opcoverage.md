# React Native Hermes HBC v96 op-coverage

- id: `hermes-opcoverage`
- ecosystem: hermes
- claim: disrobe lifts every function of a real hermesc-built HBC v96 bundle with correct names and source-matching bodies at zero fallback ops.
- measured: 100.00%
- oracle strength: strong
- CI-attested: yes [CI]
- evidence basis: self-authored sample.js compiled by the real hermesc; every function lifts at 0 fallback ops with source-matching bodies
- reproduce: `cargo test -p disrobe-pass-mobile --test real_hermes_sample`
- floor: 100.00 (holds)
- gate source: crates/disrobe-pass-mobile/tests/real_hermes_sample.rs (hbc_v96_sample_recovers_every_function_at_full_op_coverage asserts total_fallback_ops == 0)
- note: Floor equals measured (100%) because the gate asserts total_fallback_ops == 0, a hard ceiling rather than a cherry-picked figure: any regression drops below 100% and trips.
