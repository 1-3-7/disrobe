# Ruby YARV decompilation, MRI recompile-equivalence

- id: `ruby-yarv-recompile`
- ecosystem: ruby
- claim: disrobe decompiles Ruby YARV bytecode to source whose recompiled instruction multiset matches the original under the real MRI interpreter.
- measured: 98.67%
- oracle strength: strong
- CI-attested: yes [CI]
- evidence basis: real MRI (ruby): recompile the recovered source, compare the YARV opcode multiset
- reproduce: `cargo test -p disrobe-pass-ruby --test yarv_recompile_oracle`
- floor: 98.67 (holds)
- gate source: crates/disrobe-pass-ruby/tests/yarv_recompile_oracle.rs (megafile >= 98)
- note: The floor equals the measurement rather than trailing it, because yarv_recompile_oracle.rs already pins the megafile at 23648 matched of 23966 compared by equality and rejects a plotted rate its own counts do not produce. A floor beneath that pinned fraction could only absorb a change the crate gate already refuses, so the slack would be decoration.
