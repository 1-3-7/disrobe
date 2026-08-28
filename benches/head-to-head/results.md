# Head-to-head

Each leg gives `disrobe` and its leading tool the same input and scoring rule. The DEX and JAR legs use their respective committed inputs. Missing or crashing tools remain explicit result statuses, never dropped samples. Losses stay in the table.

Regenerate with `cargo run -p disrobe-bench-head-to-head`; `--check` fails if the committed measured JSON or this table drifts from a fresh run. `cargo run --locked -p disrobe-bench-head-to-head -- --check --only apk-jadx-cfr` checks only the APK result without writing it. The numbers are surfaced into the public evidence report by `cargo run -p xtask -- evidence` (the `headtohead-import` and `gate-test-harvest` oracle kinds).

## APK / DEX decompilation: disrobe vs JADX vs CFR (recompile-clean emitted methods under real javac)

- dataset: corpus/jvm/dex/EdgeCases.dex (SHA-256 fdc012bd9b9596256ee2bb319ef3e215a34b6d58c3b0856d7ea8bdb290910e26) for the DEX leg; corpus/jvm/megafile/EdgeCases-baseline.jar (SHA-256 9e68bd1344b5a0143966d80a7b53fe71b23809c18dac139b38e41edc9dd413a6) for the JAR leg; both committed, fully offline
- oracle: real javac (JDK), per-method recompile error-free against a STUBBED (empty) classpath so a wrong recovered signature cannot resolve against the original classes. The scorer first compiles the complete recovered source set. If a parse failure prevents attribution, it isolates only the implicated balanced method, field-initializer, or type region and reruns javac under a 64-round ceiling. A method in an isolated method or type region is unclean. Every other method is scored from the compiler diagnostics after attribution resumes. An unmapped parse failure certifies nothing.
- reproduce: `cargo run --locked -p disrobe-bench-head-to-head -- --check --only apk-jadx-cfr`

| tool | version | metric | value | status |
|---|---|---|---|---|
| disrobe (in-house Dalvik, DEX input) | n/a (in-process) | recompile-clean emitted methods (clean / emitted) | 60 clean / 163 emitted (36.8%) | ok |
| jadx (DEX input) | 1.5.5 | recompile-clean emitted methods (clean / emitted) | 281 clean / 303 emitted (92.7%) | ok |
| disrobe (in-house JVM, JAR input) | n/a (in-process) | recompile-clean emitted methods (clean / emitted) | 181 clean / 181 emitted (100.0%) | ok |
| cfr (JAR input) | CFR 0.152 | recompile-clean emitted methods (clean / emitted) | 152 clean / 166 emitted (91.6%) | ok |

DEX leg: `disrobe` recovers 60 clean of 163 emitted (36.8%), beside 3 compiler defects outside any method; `jadx` (1.5.5) recovers 281 clean of 303 emitted (92.7%), beside 1 compiler defect outside any method. `jadx` leads by 221 clean methods; `jadx` leads on clean rate, 92.7% to 36.8%. JAR leg: `disrobe` recovers 181 clean of 181 emitted (100.0%); `cfr` (CFR 0.152) recovers 152 clean of 166 emitted (91.6%). `disrobe` leads by 29 clean methods; `disrobe` leads on clean rate, 100.0% to 91.6%. All rows use the same stubbed real-`javac` oracle and are recompile-only. The scorer compiles the complete recovered source set first. If a parse failure prevents attribution, it isolates implicated balanced method, field-initializer, or type regions under a 64-round ceiling, then reruns javac. Methods inside isolated method or type regions are unclean; peer methods are scored only after javac reaches attribution. An unmapped or over-budget failure certifies nothing. The scorer receives source only, so the same rule binds `disrobe` and every competitor. A leg states no lead unless both sides are certified.

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
