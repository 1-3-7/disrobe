# Python .pyc decompilation, fixed CPython 3.14.5 574-module core population

- id: `py-stdlib-full`
- ecosystem: python
- claim: disrobe reaches normalized opcode-structure agreement for the majority of code objects in a fixed 574-module CPython 3.14.5 core population. The population excludes 60 idlelib and 21 turtledemo sources from that release's Lib directory.
- measured: 95.18%
- oracle strength: recompile-only
- CI-attested: no [local]
- evidence basis: CPython 3.14.5 recompiles the recovered source at optimize 0. The comparator normalizes opcode structure: it drops jump targets and most operands, removes and merges selected opcodes, omits __annotate__ code objects, and does not reject extra recovered objects. It does not establish semantic or emitted-bytecode equivalence.
- reproduce: `Set DISROBE_MEASUREMENT_EXECUTABLE to the candidate binary, DISROBE_CANDIDATE_SOURCE_IDENTITY to its recorded source identity, and DISROBE_FULL_EVIDENCE_DIR to an unused absolute directory outside the Cargo target. Run cargo test -p disrobe-pass-py-decompile --test full_stdlib_recompile_gate -- --ignored --nocapture. The gate requires CPython 3.14.5, pyc magic 2b0e0d0a, optimize 0, and module-list SHA256 cab2ea10ce57441d29f1117aa40e324fca805abf8ae80c2342cbd1ddcede028d. CI does not run this ignored 574-module measurement.`
- floor: 95.10 (holds)
- gate source: harness crates/disrobe-pass-py-decompile/tests/harness/py_arbitrary_measure.py over crates/disrobe-pass-py-decompile/tests/harness/full_modules_314.txt (574 modules, 18276 code objects, CPython 3.14.5)
