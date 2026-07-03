# PyArmor static unpack across the real-corpus free modes

- id: `pyarmor-corpus`
- ecosystem: pyarmor
- claim: disrobe statically unpacks every PyArmor sample in the committed free-mode corpus.
- measured: 72 recovered / 72 detected
- oracle strength: strong
- CI-attested: no [local]
- external oracle: static unpack + decompile of each committed PyArmor sample (real corpus; BCC and super mode remain a shared native wall)
- reproduce: `cargo test -p disrobe-pass-pyarmor --test static_unpack_corpus (local-only: license-restricted and large samples live outside the tree)`
- gate source: crates/disrobe-pass-pyarmor/tests/static_unpack_corpus.rs:10 (RECOVERY_FLOOR 72) and :172 (recovered >= 72 of 72); measured 72/72 locally 2026-06-11
- note: BCC and super mode lower the body into native code and are an information-theoretic wall shared by every static tool; the free-mode corpus is what this number covers.
