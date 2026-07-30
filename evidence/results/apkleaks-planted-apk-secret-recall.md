# apkleaks 2.6.3 secret recall on the same committed planted APK

- id: `apkleaks-planted-apk-secret-recall`
- ecosystem: recon
- claim: apkleaks 2.6.3 recalls 5 of the 8 planted secrets in the committed planted-secrets.apk, measured by running the tool rather than by quoting its documentation.
- measured: 62.50%
- oracle strength: strong
- CI-attested: no [local]
- external oracle: apkleaks 2.6.3 itself, executed over the same committed apk, with its findings compared against the same planted token list
- reproduce: `cargo test -p disrobe-bench-head-to-head published_planted_apk_secret_bars_are_pinned_by_membership (requires apkleaks 2.6.3 on PATH)`
- gate source: benches/head-to-head/src/frisk.rs test published_planted_apk_secret_bars_are_pinned_by_membership, which pins the version it grades so the row and the measured build cannot drift apart
- note: This row is asserted exact in both directions, not as a floor. Publishing more than apkleaks finds would overstate it and publishing less would flatter disrobe, so the gate requires the published membership to equal the measured membership exactly. The version is pinned in the bar label and re-checked against the version the tool reports, so the row cannot silently describe a different build. Marked ci = false because a machine without apkleaks grades this leg against nothing; the disrobe leg beside it still enforces there.
