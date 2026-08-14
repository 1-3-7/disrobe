# Dalvik body lowering and verifier attestation on real FOSS APKs

- id: `dalvik-realapk-coverage`
- ecosystem: android
- claim: disrobe lowers a Dalvik method body rather than a throw-stub for 82788 of 89516 defined methods across three real FOSS apks, and the real JVM verifier accepts 2960 of the 2994 recovered bodies that can be presented to it.
- measured: 92.60%
- oracle strength: coverage-self-reported
- CI-attested: no [local]
- evidence basis: two populations with different denominators: the 82788 of 89516 body-lowering count is the lifter counting its own output, and the 2960 of 2994 figure beside it is graded by real java -Xverify:all over bodies presented to the verifier, not over methods
- reproduce: `DISROBE_RUN_REAL_APK_TESTS=1 cargo test -p disrobe-pass-jvm --test dalvik_realworld_body_attest --test dex2jar_realworld_apks (local-only: the apks are gitignored)`
- floor: 92.40 (holds)
- gate source: crates/disrobe-pass-jvm/tests/dalvik_realworld_body_attest.rs (REAL_APK_METHOD_TOTAL 89516, SELF_REPORTED_BODIES 82906, CANDIDATE_BODIES 82874, SAMPLED_BODIES 8355, ATTESTED_PRESENTED 2989, ATTESTED_CLEAN 2975, ATTESTED_REJECTED 14, every one an equality rather than a floor, with the same counts pinned per apk in common::REAL_APKS and all 2989 verdicts pinned by name in tests/golden/dalvik_body_attest) and crates/disrobe-pass-jvm/tests/dex2jar_realworld_apks.rs (the same per-apk self-reported counts, also by equality); reference for the attested figure = java -Xverify:all rejecting malformed bytecode, not the lifter self-report
- note: The headline percentage stays coverage-self-reported because it counts lowered bodies. The attested figure beside it is external: 82756 non-stub candidate bodies, a deterministic 100-permille sample selects 8343, 2994 of those re-host into an isolated carrier and 2960 pass -Xverify:all, and the remaining 5349 are ungraded rather than passing. Every attested and rejected body is pinned by name under crates/disrobe-pass-jvm/tests/golden/dalvik_body_attest/, so one body cannot regress while a count holds. The floor is 92.4 rather than 92.5 because 82788 of 89516 is 92.4818%, so a 92.5 floor would be a bound the counts behind this row do not reach; the plotted 92.5 is the one-decimal rounding of that ratio, which the gate pins, and the floor has to sit under the ratio itself. Both figures stay local until the apks are SHA-pinned and redistributable.
