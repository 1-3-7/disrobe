# apkleaks 2.6.3 secret recall on the same committed planted APK

- id: `apkleaks-planted-apk-secret-recall`
- ecosystem: recon
- claim: apkleaks 2.6.3 recalls 5 of the 8 planted secrets in the committed planted-secrets.apk, measured by running the tool rather than by quoting its documentation.
- measured: 62.50%
- oracle strength: strong
- CI-attested: yes [CI]
- evidence basis: the raw --json output apkleaks 2.6.3 wrote over this same committed apk, captured at evidence/competitors/apkleaks-2.6.3-planted-secrets.json and hash-pinned by the provenance record beside it, with its findings compared against the same planted token list
- reproduce: `cargo test -p disrobe-bench-head-to-head published_planted_apk_secret_bars_are_pinned_by_membership, defined in benches/head-to-head/src/frisk.rs`
- gate source: benches/head-to-head/src/frisk.rs test published_planted_apk_secret_bars_are_pinned_by_membership, which pins the version it grades so the row and the measured build cannot drift apart
- note: This row is asserted exact in both directions, not as a floor. Publishing more than apkleaks finds would overstate it and publishing less would flatter disrobe, so the gate requires the published membership to equal the measured membership exactly. The graded input is the committed capture of what apkleaks 2.6.3 wrote, refused unless it hashes to the value its provenance record states and unless the apk it was taken over hashes to the committed one, so the comparison grades on every machine including CI with no install and no network. A host that does carry apkleaks 2.6.3 re-runs it, and the re-run has to agree with the capture.
