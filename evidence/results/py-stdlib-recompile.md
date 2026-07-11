# Python .pyc decompilation, per-code-object recompile-equivalence

- id: `py-stdlib-recompile`
- ecosystem: python
- claim: disrobe recovers Python source whose recompiled bytecode is equivalent to the original, per code object, across the CPython 3.14 stdlib.
- measured: 95.61%
- oracle strength: strong
- CI-attested: yes [CI]
- external oracle: CPython 3.14 (recompile the recovered source, compare emitted bytecode per code object)
- reproduce: `cargo test -p disrobe-pass-py-decompile --test arbitrary_recompile_gate`
- floor: 90.00 (holds)
- gate source: crates/disrobe-pass-py-decompile/tests/arbitrary_recompile_gate.rs:34 (OBJECT_PCT_FLOOR 90.0); harness crates/disrobe-pass-py-decompile/tests/harness/py_arbitrary_measure.py over the 200-module pinned corpus; measured live 95.61 (6010 of 6286 code objects, 200 of 200 modules, whole-module exact 60.00%, 0 sibling-count collisions) on CPython 3.14 at HEAD 4dd44212 (the main structurer caps a try/else region at the enclosing loop back-edge so the shared post-loop return is not copied into the else, recovering uuid._find_mac_near_keyword and modulefinder.ModuleFinder.find_all_submodules)
