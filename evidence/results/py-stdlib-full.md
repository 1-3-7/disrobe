# Python .pyc decompilation, full CPython 3.14 stdlib (representative)

- id: `py-stdlib-full`
- ecosystem: python
- claim: disrobe recovers recompile-equivalent source for the majority of code objects across the entire CPython 3.14 standard library, measured honestly over all 571 modules rather than a curated subset.
- measured: 92.43%
- oracle strength: strong
- CI-attested: no [local]
- external oracle: CPython 3.14 (recompile the recovered source, compare emitted bytecode per code object)
- reproduce: `python crates/disrobe-pass-py-decompile/tests/harness/py_arbitrary_measure.py over the full CPython 3.14 Lib (local-only: needs a full CPython 3.14 install)`
- floor: 88.00 (holds)
- gate source: harness crates/disrobe-pass-py-decompile/tests/harness/py_arbitrary_measure.py over all of C:/Python314/Lib (571 modules, 18262 code objects, own_equiv oracle); measured 90.63 pre-syntax-campaign, then the smtplib/pdb/codecs whole-module syntax-error fixes (+320 objects), the shared-prefix ternary-in-argument fold, and a structure_stmts re-entrancy guard that recovers recursion-runaway functions; 16880 (92.43) at HEAD 7adfad10
