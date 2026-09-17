# Luau declared-table opcode lifting coverage

- id: `lua-luau-opcode-coverage`
- ecosystem: lua
- claim: disrobe lifts 86 of the 88 opcode entries in its declared Luau table; BREAK and NEWCLASSMEMBER are decoded and reported as unresolved.
- measured: 97.73%
- oracle strength: coverage-self-reported
- CI-attested: yes [CI]
- evidence basis: none: the committed test enumerates disrobe's own declared opcode table and counts entries that avoid its unresolved-reporting path. No external semantic or upstream-format reference grades the result.
- reproduce: `cargo test -p disrobe-pass-lua --test published_luau_opcode_roster`
- gate source: crates/disrobe-pass-lua/tests/published_luau_opcode_roster.rs enumerates all 88 declared opcode values through the real lifter, pins the exact two-entry unresolved set, and checks an undeclared opcode as the mutation-kill control. This is coverage of disrobe's declared table, not an external claim about every opcode in an upstream Luau release.
- note: This is coverage of disrobe's declared table, not semantic correctness or a claim about every opcode in an upstream Luau release.
