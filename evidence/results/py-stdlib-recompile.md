# Python .pyc decompilation, per-code-object recompile-equivalence

- id: `py-stdlib-recompile`
- ecosystem: python
- claim: disrobe recovers Python source whose recompiled bytecode is equivalent to the original, per code object, across the CPython 3.14 stdlib.
- measured: 96.18%
- oracle strength: strong
- CI-attested: yes [CI]
- external oracle: CPython 3.14 (recompile the recovered source, compare emitted bytecode per code object)
- reproduce: `cargo test -p disrobe-pass-py-decompile --test arbitrary_recompile_gate`
- floor: 90.00 (holds)
- gate source: crates/disrobe-pass-py-decompile/tests/arbitrary_recompile_gate.rs:34 (OBJECT_PCT_FLOOR 90.0); harness crates/disrobe-pass-py-decompile/tests/harness/py_arbitrary_measure.py over the 200-module pinned corpus; measured live 96.18 (6046 of 6286 code objects, 200 of 200 modules) on CPython 3.14 at HEAD 8e7ea82b (an if/elif/else assert-ladder keeps its guard tests, and a guard-over-try whose handler is relocated past a cold sibling keeps the guard and its prelude)
