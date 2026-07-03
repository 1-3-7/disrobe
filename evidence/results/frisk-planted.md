# frisk recon category recall on the committed planted tree

- id: `frisk-planted`
- ecosystem: secrets
- claim: disrobe frisk detects every planted (non-secret) IOC category - endpoints, manifest findings, URLs, IPv4, email, .onion - on the committed planted ground-truth tree.
- measured: 6/6 (100.0%)
- oracle strength: strong
- CI-attested: yes [CI]
- external oracle: deliberately planted findings committed under corpus/recon/planted - the ground truth the frisk_gauntlet test asserts
- reproduce: `cargo test -p disrobe-core --test frisk_gauntlet  (harvested by cargo run -p disrobe-bench-head-to-head)`
- floor: 100.00 (holds)
- gate source: cargo test -p disrobe-core --test frisk_gauntlet (gate frisk-planted-recall, harvested by cargo run -p disrobe-bench-head-to-head)
- note: Recall against a committed planted ground truth (strong for recall). The secret-provider recall over the same tree is the frisk-apkleaks head-to-head; this row covers the non-secret IOC categories.
