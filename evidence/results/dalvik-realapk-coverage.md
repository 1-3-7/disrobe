# Dalvik body lowering and verifier attestation on real FOSS APKs

- id: `dalvik-realapk-coverage`
- ecosystem: android
- claim: disrobe lowers a Dalvik method body rather than a throw-stub for 83609 of 83943 methods that declare a code item across three real FOSS apks, and the real JVM verifier accepts 2985 of the 2998 recovered bodies that can be presented to it.
- measured: 99.60%
- oracle strength: coverage-self-reported
- CI-attested: no [local]
- evidence basis: two populations with different denominators: the 83609 of 83943 body-lowering count is the lifter counting its own output over methods that declare a code item, and the 2985 of 2998 figure beside it is graded by real java -Xverify:all over bodies presented to the verifier, not over methods
- reproduce: `DISROBE_RUN_REAL_APK_TESTS=1 cargo test -p disrobe-pass-jvm --test dalvik_realworld_body_attest --test dex2jar_realworld_apks (local-only: the apks are gitignored)`
- floor: 92.60 (holds)
- gate source: crates/disrobe-pass-jvm/tests/dalvik_realworld_body_attest.rs (REAL_APK_METHOD_TOTAL 89516, REAL_APK_CODE_ITEM_METHODS 83943, SELF_REPORTED_BODIES 83609, CANDIDATE_BODIES 83577, SAMPLED_BODIES 8414, ATTESTED_PRESENTED 2998, ATTESTED_CLEAN 2985, ATTESTED_REJECTED 13, every one an equality rather than a floor, with the same counts pinned per apk in common::REAL_APKS and all 2998 verdicts pinned by name in tests/golden/dalvik_body_attest) and crates/disrobe-pass-jvm/tests/dex2jar_realworld_apks.rs (the same per-apk self-reported counts, also by equality); reference for the attested figure = java -Xverify:all rejecting malformed bytecode, not the lifter self-report
- note: The headline percentage stays coverage-self-reported because it counts lowered bodies. The attested figure beside it is external: 83577 non-stub candidate bodies, a deterministic 100-permille sample selects 8414, 2998 of those re-host into an isolated carrier and 2985 pass -Xverify:all, and the remaining 5416 are ungraded rather than passing. Every attested and rejected body is pinned by name under crates/disrobe-pass-jvm/tests/golden/dalvik_body_attest/, so one body cannot regress while a count holds. The 92.6 floor stays below the 93.4012% declared-method contrast; the plotted 99.6% instead uses the 83943 methods that declare a code item. Both figures stay local until the apks are SHA-pinned and redistributable.
