# Python .pyc decompilation, per-code-object recompile-equivalence

- id: `py-stdlib-recompile`
- ecosystem: python
- claim: disrobe recovers Python source whose recompiled bytecode is equivalent to the original, per code object, across the CPython 3.14 stdlib.
- measured: 95.50%
- oracle strength: strong
- CI-attested: yes [CI]
- external oracle: CPython 3.14 (recompile the recovered source, compare emitted bytecode per code object)
- reproduce: `cargo test -p disrobe-pass-py-decompile --test arbitrary_recompile_gate`
- floor: 90.00 (holds)
- gate source: crates/disrobe-pass-py-decompile/tests/arbitrary_recompile_gate.rs:34 (OBJECT_PCT_FLOOR 90.0); harness crates/disrobe-pass-py-decompile/tests/harness/py_arbitrary_measure.py over the 200-module pinned corpus; measured live 95.50 (6003 of 6286 code objects, 200 of 200 modules, whole-module exact 60.00%, 0 sibling-count collisions) on CPython 3.14 at HEAD ded3aed0 (the main structurer keeps the statements between a guard and its protected try inside the if body instead of dropping them, recovering 8 previously-dropped-prelude objects across tomllib, pickle, http.server, urllib, email, mailbox, pstats, rlcompleter)
