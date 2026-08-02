# pickle corpus disassemble + symbolic-trace + safety-classification coverage

- id: `pickle-corpus`
- ecosystem: pickle
- claim: disrobe disassembles every committed pickle fixture to a STOP, symbolically executes it, and classifies benign vs malicious, matching pickletools semantics across the whole corpus.
- measured: 102/102 (100.0%)
- oracle strength: strong
- CI-attested: yes [CI]
- evidence basis: pickletools-semantics equivalence: every committed fixture must disassemble to a STOP, symbolically execute, and classify correctly (benign fixtures never flagged malicious, malicious fixtures always flagged)
- reproduce: `cargo test -p disrobe-pass-pickle --test corpus  (harvested by cargo run -p disrobe-bench-head-to-head)`
- floor: 100.00 (holds)
- gate source: cargo test -p disrobe-pass-pickle --test corpus (gate pickle-corpus-coverage, harvested by cargo run -p disrobe-bench-head-to-head)
- note: Coverage over the committed corpus is strong (the malicious/benign split is the ground truth). The fickling competitor column is a later phase; this surfaces the existing gate's number.
