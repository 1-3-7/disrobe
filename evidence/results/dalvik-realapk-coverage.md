# Dalvik body-lowering coverage on real FOSS APKs

- id: `dalvik-realapk-coverage`
- ecosystem: android
- claim: disrobe lowers a Dalvik method body (rather than a throw-stub) for the large majority of methods on real FOSS APKs.
- measured: 92.50%
- oracle strength: coverage-self-reported
- CI-attested: no [local]
- external oracle: none external: this counts methods for which the lifter returned a body vs a throw-stub (self-reported coverage, NOT verifier-attested)
- reproduce: `cargo test -p disrobe-pass-jvm --test dex2jar_realworld_apks (local-only: the APKs are gitignored)`
- floor: 88.00 (holds)
- gate source: crates/disrobe-pass-jvm/tests/dex2jar_realworld_apks.rs:33 (min_bodies_pct 92.3, self-reported bodies_recovered); measured 92.5 per commit 121ba38; verifier attestation is the committed-corpus bar above
- note: This is a coverage number, not a correctness number. It is graded against nothing external (disrobe asserting it produced output). The verifier-attested correctness number is the dalvik-verifier descriptor. Phase 2 upgrades this to a verifier-attested or dex2jar-differential number on SHA-pinned FOSS APKs before it earns a competitor column.
