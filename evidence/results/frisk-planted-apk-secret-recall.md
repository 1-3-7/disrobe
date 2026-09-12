# frisk secret recall on the committed planted APK

- id: `frisk-planted-apk-secret-recall`
- ecosystem: recon
- claim: disrobe frisk recalls all 8 planted secrets in the committed planted-secrets.apk, and each of the 8 is named individually so one cannot lapse while another starts being found.
- measured: 100.00%
- oracle strength: strong
- CI-attested: yes [CI]
- evidence basis: the planted token list committed alongside the apk, which is independent of what frisk reports; a scanner that misses a planted token fails regardless of what else it finds
- reproduce: `cargo test -p disrobe-bench-head-to-head published_planted_apk_secret_bars_are_pinned_by_membership`
- gate source: benches/head-to-head/src/frisk.rs test published_planted_apk_secret_bars_are_pinned_by_membership, which scans the committed apk and asserts every named secret is recalled; the ground truth is the planted token list, not frisk's own output
- note: The oracle is independent of the tool, but the corpus is one we authored, so read the figure as full recall on a corpus of our choosing rather than as recall on secrets in the wild. The apkleaks 2.6.3 bar beside it scores 5 of the same 8 on the same file, which is what keeps the corpus from being read as tuned to disrobe alone. The denominator is pinned by equality, so a run that inspects fewer planted secrets scores worse instead of shrinking its own universe.
