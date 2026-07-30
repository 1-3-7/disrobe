# Ruby YARV decompilation, MRI recompile-equivalence

- id: `ruby-yarv-recompile`
- ecosystem: ruby
- claim: disrobe decompiles Ruby YARV bytecode to source whose recompiled instruction multiset matches the original under the real MRI interpreter.
- measured: 98.67%
- oracle strength: strong
- CI-attested: yes [CI]
- external oracle: real MRI (ruby): recompile the recovered source, compare the YARV opcode multiset
- reproduce: `cargo test -p disrobe-pass-ruby --test yarv_recompile_oracle`
- floor: 98.00 (holds)
- gate source: crates/disrobe-pass-ruby/tests/yarv_recompile_oracle.rs (megafile >= 98)
