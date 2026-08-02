# Python .pyc decompilation, per-code-object recompile-equivalence

- id: `py-stdlib-recompile`
- ecosystem: python
- claim: disrobe recovers Python source whose recompiled bytecode is equivalent to the original, per code object, across the CPython 3.14 stdlib.
- measured: 96.60%
- oracle strength: strong
- CI-attested: yes [CI]
- evidence basis: CPython 3.14 (recompile the recovered source, compare emitted bytecode per code object)
- reproduce: `cargo test -p disrobe-pass-py-decompile --test arbitrary_recompile_gate`
- floor: 96.60 (holds)
- gate source: crates/disrobe-pass-py-decompile/tests/arbitrary_recompile_gate.rs:17 (OBJECT_PCT_FLOOR 96.60); harness crates/disrobe-pass-py-decompile/tests/harness/py_arbitrary_measure.py over the 200-module pinned corpus; measured live 96.6 (6072 of 6286 code objects, 200 of 200 modules) on CPython 3.14.5 (a pure-or if-guard whose short-circuit exits reach an inlined terminator reassembles into a single if a or b: body, and a loop after a with recurses through the statement structurer instead of collapsing to a tuple assignment)
