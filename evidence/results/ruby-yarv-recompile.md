# Ruby YARV decompilation, opcode-name recall after recompilation

- id: `ruby-yarv-recompile`
- ecosystem: ruby
- claim: disrobe recovers YARV source accepted by MRI's compiler; the benchmark measures original opcode-name multiset recall across the compiled instruction sequences.
- measured: 98.67%
- oracle strength: recompile-only
- CI-attested: yes [CI]
- evidence basis: MRI compiles original and recovered sources without executing them. The comparison sums the smaller count for each opcode name and divides by the original instruction count. It ignores order, operands, constants, branch targets, and instruction ownership, and does not penalize additional recovered instructions.
- reproduce: `Set DISROBE_RUBY to MRI 3.4.10 and DISROBE_YARV_EVIDENCE_DIR to a new absolute directory outside Cargo build output, with an existing parent. Run cargo test -p disrobe-pass-ruby --test yarv_recompile_oracle -- --nocapture. Each fixture retains its source, disassembly, opcode counts, tool identities, and SHA-256 hashes.`
- floor: 98.67 (holds)
- gate source: crates/disrobe-pass-ruby/tests/yarv_recompile_oracle.rs (megafile >= 98)
