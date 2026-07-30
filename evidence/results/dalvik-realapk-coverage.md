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
- gate source: crates/disrobe-pass-jvm/tests/dalvik_realworld_body_attest.rs (REAL_APK_METHOD_TOTAL 89516 and ATTESTED_PRESENTED 2994 pinned by equality, SELF_REPORTED_BODY_FLOOR 82788, ATTESTED_CLEAN_FLOOR 2960, ATTESTED_FAIL_CEILING 34, per-apk pins in common::REAL_APKS) and crates/disrobe-pass-jvm/tests/dex2jar_realworld_apks.rs (per-apk self-reported numerator floors against equality-pinned method totals); reference for the attested figure = java -Xverify:all rejecting malformed bytecode, not the lifter self-report
- note: This is a coverage number, not a correctness number. It is graded against nothing external (disrobe asserting it produced output). The verifier-attested correctness number is the dalvik-verifier descriptor. Phase 2 upgrades this to a verifier-attested or dex2jar-differential number on SHA-pinned FOSS APKs before it earns a competitor column.
