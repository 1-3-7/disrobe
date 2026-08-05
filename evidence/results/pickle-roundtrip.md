# pickle reconstruction roundtrip: re-execution equivalence under real CPython

- id: `pickle-roundtrip`
- ecosystem: pickle
- claim: Every committed pickle fixture reconstructs to a value that re-executes equivalently under a real CPython interpreter, and a case walled as an information-theoretic ceiling is refused rather than counted toward the denominator.
- measured: 100.00%
- oracle strength: strong
- CI-attested: yes [CI]
- evidence basis: real CPython: the reconstructed value is written back out and executed by the interpreter, and the result is compared with the original fixture's execution. The reference is the interpreter, never disrobe's own reconstruction.
- reproduce: `cargo test -p disrobe-pass-pickle --test roundtrip`
- floor: 100.00 (holds)
- gate source: crates/disrobe-pass-pickle/tests/roundtrip.rs pins PINNED_FIXTURES = 470 and PINNED_REEXECUTED = 470, names the bar `reconstruction roundtrip, re-executed` that it grades, reconstructs every committed fixture, and re-executes each under a real CPython interpreter. An absent interpreter is fatal on every host, so the case cannot pass while grading nothing. It carries its own emptiness check: dropping one re-executed case must produce a defect naming what this run reconstructed.
- note: Distinct from the pickle-corpus descriptor, which grades disassembly and safety classification against pickletools semantics over a different population. This one grades reconstruction by running it. The gate refuses a wall: a case declared an information-theoretic ceiling is not counted as recovered, so walling a hard case shrinks the numerator instead of inflating the rate. It carries its own emptiness check, `the_pinned_roundtrip_check_rejects_a_dropped_fixture_and_a_shrunken_denominator`, which asserts that dropping one re-executed case produces a defect naming what the run reconstructed. An absent interpreter is fatal on every host and cannot be downgraded by an environment variable, because a case that grades nothing must not report success; DISROBE_PYTHON only selects which interpreter is used.
