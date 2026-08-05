# Head-to-head

Each leg gives `disrobe` and its leading tool the same input and scoring rule. The DEX and JAR legs use their respective committed inputs. Missing or crashing tools remain explicit result statuses, never dropped samples. Losses stay in the table.

Regenerate with `cargo run -p disrobe-bench-head-to-head`; `--check` fails if the committed measured JSON or this table drifts from a fresh run. `cargo run --locked -p disrobe-bench-head-to-head -- --check --only apk-jadx-cfr` checks only the APK result without writing it. The numbers are surfaced into the public evidence report by `cargo run -p xtask -- evidence` (the `headtohead-import` and `gate-test-harvest` oracle kinds).

## APK / DEX decompilation: disrobe vs JADX vs CFR (recompile-clean main-class methods under real javac)

- dataset: corpus/jvm/dex/EdgeCases.dex (SHA-256 fdc012bd9b9596256ee2bb319ef3e215a34b6d58c3b0856d7ea8bdb290910e26) for the DEX leg; corpus/jvm/megafile/EdgeCases-baseline.jar (SHA-256 9e68bd1344b5a0143966d80a7b53fe71b23809c18dac139b38e41edc9dd413a6) for the JAR leg; both committed, fully offline
- oracle: real javac (JDK), per-method recompile error-free against a STUBBED (empty) classpath so a wrong recovered signature cannot resolve against the original classes. A method is certified clean only from a file javac type-checked end to end; javac reports no method-level result for a file it stopped parsing, so such a file certifies nothing rather than scoring zero
- reproduce: `cargo run --locked -p disrobe-bench-head-to-head -- --check --only apk-jadx-cfr`

| tool | version | metric | value | status |
|---|---|---|---|---|
| disrobe (in-house Dalvik, DEX input) | n/a (in-process) | recompile-clean main-class methods (clean / emitted) | not certified: 132 methods emitted | uncertified |
| jadx (DEX input) | 1.5.5 | recompile-clean main-class methods (clean / emitted) | not certified: 130 methods emitted | uncertified |
| disrobe (in-house JVM, JAR input) | n/a (in-process) | recompile-clean main-class methods (clean / emitted) | 131 clean / 131 emitted (100.0%) | ok |
| cfr (JAR input) | CFR 0.152 | recompile-clean main-class methods (clean / emitted) | not certified: 106 methods emitted | uncertified |

DEX leg: `disrobe` recovers 132 emitted methods, none of them certified, because javac stopped at a defect on line 2 of the recovered file; `jadx` (1.5.5) recovers 130 emitted methods, none of them certified, because javac stopped at a defect on line 619 of the recovered file. No lead is stated, because the compiler did not certify both sides. JAR leg: `disrobe` recovers 131 clean of 131 emitted (100.0%); `cfr` (CFR 0.152) recovers 106 emitted methods, none of them certified, because javac stopped at a defect on line 173 of the recovered file. No lead is stated, because the compiler did not certify both sides. All rows use the same stubbed real-`javac` oracle and are recompile-only. A method counts clean only when javac type-checked the whole recovered file: a file the compiler stopped parsing certifies nothing, for either side, and is reported with the method count its tool did emit rather than as a zero. The same rule scores `disrobe` and every competitor, and a leg states no lead unless the compiler certified both of its sides.

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
