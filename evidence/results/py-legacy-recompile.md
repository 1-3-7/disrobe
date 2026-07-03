# CPython legacy 1.0-3.7 proven-correct decompilation

- id: `py-legacy-recompile`
- ecosystem: python
- claim: disrobe decompiles legacy CPython bytecode (1.0 through 3.7) to source that is proven correct by recompile-equivalence or, where the period interpreter is absent, a structural token-match against the original .py.
- measured: 78.50%
- oracle strength: strong
- CI-attested: yes [CI]
- external oracle: period CPython interpreters 1.0-3.7 (recompile-equivalence) or original .py source (structural token-match)
- reproduce: `cargo test -p disrobe-pass-py-decompile --test legacy_recompile`
- floor: 78.00 (holds)
- gate source: crates/disrobe-pass-py-decompile/tests/legacy_recompile.rs:31 (PROVEN_CORRECT_FLOOR 150, CI-enforced via the test job); 166/191 measured locally 2026-06-12 with python 1.0-3.12 present
