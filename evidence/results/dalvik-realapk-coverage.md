# Dalvik body lowering and verifier attestation on real FOSS APKs

- id: `dalvik-realapk-coverage`
- ecosystem: android
- claim: disrobe lowers 83662 of 83943 methods with a code item across three real FOSS APKs, and the JVM verifier accepts 2988 of 2998 recovered bodies presented in isolated carriers.
- measured: 99.70%
- oracle strength: coverage-self-reported
- CI-attested: no [local]
- evidence basis: two populations with different denominators: 83662 of 83943 is the lifter's body-lowering count over methods with a code item; 2988 of 2998 is acceptance by java -Xverify:all of recovered bodies presented in isolated carriers
- reproduce: `DISROBE_RUN_REAL_APK_TESTS=1 cargo test -p disrobe-pass-jvm --test dalvik_realworld_body_attest --test dex2jar_realworld_apks (local-only: the apks are gitignored)`
- floor: 92.60 (holds)
- gate source: crates/disrobe-pass-jvm/tests/dalvik_realworld_body_attest.rs enforces the aggregate and per-APK counts against common::REAL_APKS, which pins each input SHA-256. tests/golden/dalvik_body_attest pins all 2998 verifier verdicts by method name. dex2jar_realworld_apks.rs independently checks the per-APK lowering counts. The attestation uses java -Xverify:all without invoking recovered methods.
- note: The lowering percentage is self-reported. Of 83630 non-stub candidate bodies, deterministic 100-permille sampling selects 8419; 2998 can be re-hosted in isolated carriers, 2988 pass -Xverify:all, and 5421 sampled bodies remain excluded from that grade. Attested and rejected bodies are pinned by name under crates/disrobe-pass-jvm/tests/golden/dalvik_body_attest/. The three APKs are SHA-pinned but fetched separately, so this measurement remains local. The body-lowering denominator is 83943 methods with code items, not all 89516 defined methods.
