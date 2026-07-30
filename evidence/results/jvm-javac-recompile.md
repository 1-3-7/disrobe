# JVM classfile decompilation, per-method javac recompile

- id: `jvm-javac-recompile`
- ecosystem: jvm
- claim: disrobe decompiles JVM bytecode to Java that recompiles error-free under the real javac, per method, across the EdgeCases corpus.
- measured: 100.00%
- oracle strength: recompile-only
- CI-attested: yes [CI]
- external oracle: real javac (JDK 25): recovered Java must recompile error-free per method
- reproduce: `cargo test -p disrobe-pass-jvm --test decompile_recompile_rate`
- floor: 100.00 (holds)
- gate source: crates/disrobe-pass-jvm/tests/decompile_recompile_rate.rs (report_per_method_javac_recompile asserts ok >= PER_METHOD_JAVAC_OK_FLOOR 131 of PER_METHOD_JAVAC_TOTAL 131); CI runs it via the test job with actions/setup-java (JDK 25); floor measured 2026-06-22 after fixing the pickWord-unmasked defects
- note: Oracle strength is recompile-only: the recovered source compiling is necessary but not sufficient for equivalence (a dropped branch can still compile). The .pyc gate is the stronger standard (recompile-equivalent). Upgrade to bytecode-equivalence is tracked for a later phase.
