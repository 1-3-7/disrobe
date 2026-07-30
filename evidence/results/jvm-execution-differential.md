# JVM classfile decompilation, per-method execution differential

- id: `jvm-execution-differential`
- ecosystem: jvm
- claim: disrobe decompiles JVM bytecode to Java whose observable per-method behavior under a real JVM matches the original, across the EdgeCases corpus.
- measured: 89.31%
- oracle strength: strong
- CI-attested: yes [CI]
- external oracle: real javac (JDK 25) plus a real JVM: the original and the recovered source are each compiled and run, and every observable per-method result is compared
- reproduce: `cargo test -p disrobe-pass-jvm --test edgecases_execution_differential`
- floor: 89.31 (holds)
- gate source: crates/disrobe-pass-jvm/tests/edgecases_execution_differential.rs (EXECUTION_EQUIVALENT_FLOOR 117 of PER_METHOD_TOTAL 131, with the equivalent set pinned as a membership list of method names rather than a count, so a method cannot leave it silently and the pinned-divergent lists only ever shrink); the reference is real javac plus a real JVM comparing observable behaviour, never the decompiler's own output; the_execution_differential_reports_a_double_counted_exception_path injects a second counter increment on divSafe's recovered exception path and requires this differential to report divergence while javac still accepts the file; measured 117 equivalent, 8 divergent, 6 not driven on JDK 25
- note: This is the strong companion to jvm-javac-recompile, which is recompile-only over the same 131-method denominator. Recompile-acceptance proves the recovered Java compiles, not that it behaves the same; this crate once emitted a method that compiled cleanly and incremented a counter twice on its exception path. The equivalent set is pinned as a membership list of method names rather than a count, so a method cannot leave it silently. The residual 14 is two populations: 8 javac-clean but measurably divergent, and 6 javac-clean but not executable in isolation, which are ungraded rather than passing. Publish both bars; do not blend them.
