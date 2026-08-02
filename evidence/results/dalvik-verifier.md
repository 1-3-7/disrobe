# Dalvik recovered bodies, real JVM verifier

- id: `dalvik-verifier`
- ecosystem: android
- claim: disrobe re-hosts Dalvik method bodies into class bytecode that the real JVM bytecode verifier accepts under -Xverify:all, on the committed dex corpus.
- measured: 100.00%
- oracle strength: strong
- CI-attested: yes [CI]
- external oracle: real JVM verifier (-Xverify:all over the assembled jar; the JVM rejects malformed bytecode)
- reproduce: `cargo test -p disrobe-pass-jvm --test dalvik_verifier_gate`
- floor: 100.00 (holds)
- gate source: crates/disrobe-pass-jvm/tests/dalvik_verifier_gate.rs (COMMITTED_VERIFY_CLEAN_CLASSES 118, COMMITTED_LIFTER_VERIFY_FAILURES 0, COMMITTED_CORPUS_CLASSES 155, COMMITTED_BODY_VERIFY_CLEAN 317, COMMITTED_BODY_VERIFY_FAILURES 0, every one an equality rather than a floor); reference = -Xverify:all over assemble_jar output, not the lifter self-report; measured 118 of 118 verifier-presented classes with 37 link-skipped and 317 re-hosted bodies clean on JDK 25, and because the corpus is committed and the translation deterministic, a figure that moves either way fails this gate until the documents state the new one
