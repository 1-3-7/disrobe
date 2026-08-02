# Python .pyc decompilation, full CPython 3.14 stdlib (representative)

- id: `py-stdlib-full`
- ecosystem: python
- claim: disrobe recovers recompile-equivalent source for the majority of code objects across the entire CPython 3.14 standard library, measured over all 574 modules rather than a curated subset.
- measured: 95.09%
- oracle strength: strong
- CI-attested: no [local]
- evidence basis: CPython 3.14 (recompile the recovered source, compare emitted bytecode per code object)
- reproduce: `python crates/disrobe-pass-py-decompile/tests/harness/py_arbitrary_measure.py over the full CPython 3.14 Lib, the population crates/disrobe-pass-py-decompile/tests/full_stdlib_recompile_gate.rs measures under --ignored; CI does not run that gate and re-derives only the 115-module slice beside it`
- floor: 95.00 (holds)
- gate source: harness crates/disrobe-pass-py-decompile/tests/harness/py_arbitrary_measure.py over crates/disrobe-pass-py-decompile/tests/harness/full_modules_314.txt (574 modules, 18276 code objects, CPython 3.14.5)
