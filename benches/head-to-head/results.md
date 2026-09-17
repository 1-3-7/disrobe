# Head-to-head

Each leg gives `disrobe` and the comparison tool the same input and scoring rule. The DEX and JAR legs use their respective committed inputs. A missing, failed, or uncertified required tool aborts regeneration before a result is published.

Regenerate with `cargo run --locked -p disrobe-bench-head-to-head`. Add `-- --check` to compare a fresh run with the committed results, or `-- --check --only apk-jadx-cfr` to check the APK measurement. `cargo run --locked -p xtask -- evidence` updates the public evidence report.

## APK / DEX decompilation: emitted-region compile yield under real javac

- dataset: corpus/jvm/dex/EdgeCases.dex (SHA-256 fdc012bd9b9596256ee2bb319ef3e215a34b6d58c3b0856d7ea8bdb290910e26) for the DEX leg; corpus/jvm/megafile/EdgeCases-baseline.jar (SHA-256 9e68bd1344b5a0143966d80a7b53fe71b23809c18dac139b38e41edc9dd413a6) for the JAR leg; both committed, fully offline
- method: javac compiles the complete recovered source set against a stubbed classpath that excludes the original classes. If a parse error prevents attribution, the scorer isolates the implicated balanced method, field-initializer, or type region and reruns javac, up to 64 rounds. Methods in isolated regions fail; remaining methods are graded from compiler diagnostics. Unmapped parse errors leave the result uncertified.
- reproduce: `cargo run --locked -p disrobe-bench-head-to-head -- --check --only apk-jadx-cfr`

| tool | version | metric | value | status |
|---|---|---|---|---|
| disrobe (in-house Dalvik, DEX input) | n/a (in-process) | emitted-region compile yield (clean / emitted) | 63 clean / 163 emitted (38.7%) | ok |
| jadx (DEX input) | 1.5.5 | emitted-region compile yield (clean / emitted) | 281 clean / 303 emitted (92.7%) | ok |
| disrobe (in-house JVM, JAR input) | n/a (in-process) | emitted-region compile yield (clean / emitted) | 181 clean / 181 emitted (100.0%) | ok |
| cfr (JAR input) | CFR 0.152 | emitted-region compile yield (clean / emitted) | 152 clean / 166 emitted (91.6%) | ok |

DEX leg: `disrobe` emitted-region compile yield: 63 clean of 163 emitted (38.7%), beside 1 compiler defect outside any method; `jadx` (1.5.5): 281 clean of 303 emitted (92.7%), beside 1 compiler defect outside any method. The denominators describe different emitted-region populations and do not support a cross-tool ranking. JAR leg: `disrobe` emitted-region compile yield: 181 clean of 181 emitted (100.0%); `cfr` (CFR 0.152): 152 clean of 166 emitted (91.6%). The denominators describe different emitted-region populations and do not support a cross-tool ranking. All rows use the same stubbed real-`javac` procedure. The scorer compiles the complete emitted source set first. If a parse failure prevents attribution, it isolates implicated balanced method, field-initializer, or type regions under a 64-round ceiling, then reruns javac. Regions inside an isolated method or type are unclean; peer regions are scored only after javac reaches attribution. An unmapped or over-budget failure certifies nothing. Each ratio describes only that tool's emitted regions.

## Secret recall: disrobe frisk and APKLeaks

- dataset: corpus/recon/apk/planted-secrets.apk contains 8 planted secrets across smali, res/raw, res/values, and assets
- method: exact-token recall against the same 8 planted secrets for both tools
- denominator: 8 planted high-value secrets (fixed, identical for both tools)
- reproduce: `cargo run --locked -p disrobe-bench-head-to-head -- --check --only frisk-apkleaks`

| tool | version | metric | value | status |
|---|---|---|---|---|
| disrobe frisk (in-process recon engine) | n/a (in-process) | recall % | 8/8 (100.0%) | ok |
| apkleaks | v2.6.3 | recall % | 5/8 (62.5%) | ok |

`disrobe frisk` recalls 100.0% of the planted secrets; apkleaks recalls 62.5%. apkleaks did not match: AWS secret access key, HTTP Basic auth credential, session JWT. This row scores only the shared 8-secret ground truth.

## Gate-test harvest: independently graded recovery checks
