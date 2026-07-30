# Head-to-head

Each comparison gives `disrobe` and the leading tool the same input, same oracle, and same denominator. Missing or crashing tools count as misses, not dropped samples. Losses stay in the table.

Regenerate with `cargo run -p disrobe-bench-head-to-head`; `--check` fails if the committed measured JSON or this table drifts from a fresh run. The numbers are surfaced into the public evidence report by `cargo run -p xtask -- evidence` (the `headtohead-import` and `gate-test-harvest` oracle kinds).

## APK / DEX decompilation: disrobe vs JADX vs CFR (recompile-clean main-class methods under real javac)

- dataset: corpus/jvm/dex/EdgeCases.dex (SHA-256 fdc012bd...) for the DEX leg; corpus/jvm/megafile/EdgeCases-baseline.jar (SHA-256 9e68bd13...) for the JAR leg; both committed, fully offline
- oracle: real javac (JDK), per-method recompile error-free against a STUBBED (empty) classpath so a wrong recovered signature cannot resolve against the original classes
- reproduce: `cargo run -p disrobe-bench-head-to-head  (needs javac + jadx + cfr on PATH)`

| tool | version | metric | value | status |
|---|---|---|---|---|
| disrobe (in-house Dalvik, DEX input) | n/a (in-process) | recompile-clean main-class methods (clean / emitted) | 129 clean / 132 emitted (97.7%) | ok |
| jadx (DEX input) | 1.5.5 | recompile-clean main-class methods (clean / emitted) | 128 clean / 130 emitted (98.5%) | ok |
| disrobe (in-house JVM, JAR input) | n/a (in-process) | recompile-clean main-class methods (clean / emitted) | 131 clean / 131 emitted (100.0%) | ok |
| cfr (JAR input) | CFR 0.152 | recompile-clean main-class methods (clean / emitted) | 105 clean / 106 emitted (99.1%) | ok |

DEX leg: `disrobe` recovers 129 clean of 132 emitted (97.7%); `jadx` (1.5.5) recovers 128 clean of 130 emitted (98.5%). `disrobe` leads by 1 clean method; `jadx` leads on clean rate, 98.5% to 97.7%. JAR leg: `disrobe` recovers 131 clean of 131 emitted (100.0%); `cfr` (CFR 0.152) recovers 105 clean of 106 emitted (99.1%). `disrobe` leads by 26 clean methods; `disrobe` leads on clean rate, 100.0% to 99.1%. All rows use the same stubbed real-`javac` oracle and are recompile-only.

## Secret / IOC recall: disrobe frisk vs apkleaks (same APK, hand-verified planted ground truth)

- dataset: corpus/recon/apk/planted-secrets.apk (committed, fully offline) with 8 hand-verified planted high-value secrets across smali, res/raw, res/values, and assets
- oracle: recall against the hand-verified planted ground-truth set: disrobe matches by its rule_id or the raw token (frisk redacts secret previews by design), apkleaks matches by the raw token its rule reports; both against the same 8-secret ground truth
- shared denominator: 8 planted high-value secrets (fixed, identical for both tools)
- reproduce: `cargo run -p disrobe-bench-head-to-head  (apkleaks installed via evidence/competitors/install-linux.sh; needs jadx on PATH for apkleaks's decompile step. apkleaks rule set pinned at evidence/competitors/apkleaks-regexes.json 2.6.3)`

| tool | version | metric | value | status |
|---|---|---|---|---|
| disrobe frisk (in-process recon engine) | n/a (in-process) | recall % | 8/8 (100.0%) | ok |
| apkleaks | v2.6.3 | recall % | 5/8 (62.5%) | ok |

`disrobe frisk` recalls 100.0% of the planted secrets; apkleaks recalls 62.5%. apkleaks misses the AWS key, HTTP Basic credential, and JWT. This row scores only the shared 8-secret ground truth.

## Gate-test harvest: real oracle gates with no recovery.json number, surfaced
