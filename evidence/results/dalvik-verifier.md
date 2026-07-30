# Dalvik recovered bodies, real JVM verifier

- id: `dalvik-verifier`
- ecosystem: android
- claim: disrobe re-hosts Dalvik method bodies into class bytecode that the real JVM bytecode verifier accepts under -Xverify:all, on the committed dex corpus.
- measured: 100.00%
- oracle strength: strong
- CI-attested: yes [CI]
- external oracle: real JVM verifier (-Xverify:all over the assembled jar; the JVM rejects malformed bytecode)
- reproduce: `cargo test -p disrobe-pass-jvm --test dalvik_verifier_gate`
- floor: 97.00 (holds)
- gate source: crates/disrobe-pass-jvm/tests/dalvik_verifier_gate.rs (VERIFY_CLEAN_CLASS_FLOOR 118, LIFTER_VERIFY_FAIL_CEILING 0, LINK_SKIPPED_CEILING 37, COMMITTED_CORPUS_CLASSES 155, BODY_VERIFY_CLEAN_FLOOR 317, BODY_VERIFY_FAIL_CEILING 0); reference = -Xverify:all over assemble_jar output, not the lifter self-report; measured 118 of 118 verifiable classes with 37 link-skipped and 317 re-hosted bodies clean on JDK 25, so each floor is pinned at the figure the corpus measures rather than beneath it
