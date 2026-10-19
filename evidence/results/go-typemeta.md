# Go type names on stripped go1.26.3 linux/amd64, graded against go tool nm

- id: `go-typemeta`
- ecosystem: go
- claim: disrobe recovers the same names at the same addresses for all 115 type descriptors named by the independent nm oracle after the fixture's symbol table, string table and DWARF are removed.
- measured: 100.00%
- oracle strength: strong
- CI-attested: yes [CI]
- evidence basis: committed go tool nm output from the unstripped compiler build; equality-function symbols and go:itab descriptors define the reference population independently of the recovery walk
- reproduce: `cargo test -p disrobe-pass-go --all-features --test go_matrix_reference -- --nocapture`
- floor: 100.00 (holds)
- gate source: crates/disrobe-pass-go/tests/go_matrix_reference.rs: published_go_type_name_bar_is_the_nm_graded_stripped_build re-derives num and den from corpus/go/versions/go126_linux_amd64 and its committed go tool nm output (build and reference commands with sha256 in corpus/go/MANIFEST.toml); the four *_matrix_matches_nm_and_objdump_references tests pin each row's population counts and require zero mismatches; matrix_grades_turn_red_on_mutated_references renames or shifts one reference entry per class and requires exactly one mismatch; a type-name walk that kept the extra '*' the compiler stores in front of non-pointer type strings measured 110 of 115 on this build and failed every itab pair
- note: The published population is corpus/go/versions/go126_linux_amd64, built and referenced by the commands and hashes in corpus/go/MANIFEST.toml. The matrix also covers Go 1.17, 1.18 and 1.20, PIE and arm64. Name and address mutations must make the grade fail. This is the nm-addressed population, not every type in the program; the separate Windows DWARF oracle recovers 485 of 699 runtime types.
