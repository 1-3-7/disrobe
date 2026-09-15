# pickle reconstruction roundtrip: re-execution equivalence under real CPython

- id: `pickle-roundtrip`
- ecosystem: pickle
- claim: All 470 generated Pickle fixtures pass CPython re-execution comparison checks, including type and value comparisons and identity checks for shared and cyclic container cases.
- measured: 100.00%
- oracle strength: strong
- CI-attested: yes [CI]
- evidence basis: CPython loads each original pickle, executes the reconstructed program, and compares the resulting values. The benchmark includes type and value comparisons and identity checks for shared and cyclic container cases.
- reproduce: `cargo test -p disrobe-pass-pickle --test roundtrip`
- floor: 100.00 (holds)
- gate source: crates/disrobe-pass-pickle/tests/roundtrip.rs runs the `reconstruction roundtrip, re-executed` measurement. Its roundtrip_harness.py emits 470 fixtures for protocols 0 through 5 at test time; CPython loads each original pickle, executes the reconstructed program, and compares the results. The measurement does not cover inputs requiring a runtime copyreg registry, out-of-band buffers, persistent IDs, or unavailable importable modules. `DISROBE_PYTHON` selects the interpreter.
- note: Distinct from the pickle-corpus descriptor, which grades disassembly and safety classification against pickletools semantics over a different population. This measurement emits 470 fixtures for protocols 0 through 5 at test time, reconstructs each one, and compares its executed result with CPython's `pickle.loads` result. It does not establish recovery for inputs that require a runtime copyreg registry, out-of-band buffers, persistent IDs, or unavailable importable modules. `DISROBE_PYTHON` selects the CPython interpreter used for the measurement.
