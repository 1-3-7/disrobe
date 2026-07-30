# Go type-name recovery on a stripped go1.26.3 binary

- id: `go-typemeta`
- ecosystem: go
- claim: disrobe recovers Go type names from a -s -w stripped binary by walking typelinks and moduledata, verified against the real go1.26.3 toolchain's own type metadata.
- measured: 100.00%
- oracle strength: strong
- CI-attested: yes [CI]
- external oracle: real go1.26.3 toolchain output (recovered type names compared against the toolchain's own typelinks/moduledata)
- reproduce: `cargo test -p disrobe-pass-go --test go_typemeta`
- floor: 84.00 (holds)
- gate source: crates/disrobe-pass-go/tests/go_typemeta.rs (typemeta_recovers_real_type_names_on_go126 asserts the type total equals 838 and the recovered count is at least 838 on common::HELLO_STRIPPED, with ratio >= 0.85 kept as a secondary guard); the stripped fixture is force-committed (git add -f, overriding the crates/disrobe-pass-go/tests/fixtures/*.exe gitignore) so the gate runs in CI; the garble/embed/generics/magic-stomp fixtures are force-committed the same way so those gates also run; 528/528 measured on go1.26.3 2026-06-12
