# Python .pyc decompilation, normalized opcode-structure agreement

- id: `py-stdlib-recompile`
- ecosystem: python
- claim: disrobe reaches normalized opcode-structure agreement for code objects in a 200-module pinned CPython 3.14.5 corpus.
- measured: 97.66%
- oracle strength: recompile-only
- CI-attested: yes [CI]
- evidence basis: CPython 3.14.5 recompiles the recovered source. The comparator drops jump targets and most operands, removes and merges selected opcodes, omits __annotate__ code objects, and does not reject extra recovered objects; it does not establish semantic or emitted-bytecode equivalence.
- reproduce: `cargo test -p disrobe-pass-py-decompile --test it arbitrary_recompile_gate::`
- floor: 96.51 (holds)
- gate source: evidence/results/captured/python-stdlib-full.json records the accepted capture and its pinned subset. crates/disrobe-pass-py-decompile/tests/arbitrary_recompile_gate.rs enforces this bar's floor_pct as OBJECT_PCT_FLOOR and its modules_exact count of wholly matching modules as MODULES_EXACT_FLOOR. The shared py_arbitrary_measure.py harness defines both populations.
