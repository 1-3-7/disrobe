# JVM and Android

`disrobe` decompiles JVM classfiles and Android DEX through a unified command, adding obfuscator reversal, ProGuard/R8 mapping replay, and chain auto-detection, and wrapping the best FOSS decompilers headlessly when you want one.

## At a glance

| Surface | Support |
|---|---|
| Inputs | `.class`, `.jar`, `.dex`, `.apk`; the classfile itself validated in-house (format 1.0.2-25) |
| Decompilers | In-house classfile and Dalvik decompilers, the Dalvik one default on `.dex` and `.apk`; CFR, Vineflower, Procyon, JADX, and others via `--backend` |
| Language surface | Records, sealed types, pattern matching, enum constant bodies, declaration and member annotations, enhanced `for`, multi-`catch`, plus Kotlin and Scala idioms |
| Obfuscators reversed | Zelix KlassMaster, Allatori, Stringer, DashO, DexGuard control flow, BlackObfuscator flattening; ProGuard/R8 names replayed from `mapping.txt` |
| Families detected (<!-- m:jvm_families -->10<!-- /m -->) | ProGuard/R8, Zelix KlassMaster, Allatori, Stringer, DashO, DexGuard, BlackObfuscator, yGuard, SkidSuite2, JBCO (the last three detect-only) |
| RASP vendors (<!-- m:rasp_vendors -->8<!-- /m -->) | Promon SHIELD, Guardsquare DexGuard RASP and ThreatCast, Appdome, OneSpan, Arxan/Digital.ai, Zimperium zShield, Licel DexProtector |
| Signatures | APK signature schemes v1 (JAR) through v4 verified |

## Commands

```sh
disrobe jvm decompile App.class --out src/
disrobe jvm decompile app.jar --backend vineflower --out src/
disrobe jvm decompile app.apk --backend jadx --out src/
disrobe jvm decompile classes.dex --backend jadx --out src/
disrobe jvm decompile app.jar --mapping mapping.txt --out src/   # replay ProGuard/R8 names
disrobe jvm extract app.apk --out classes/    # extract a .jar / .apk + dump classfile inventory
disrobe jvm backends                          # report available JVM/Android backends on PATH
disrobe auto app.apk --out recovered/         # APK -> dex -> JADX + Smali + manifest
```

`decompile` routes a `.class`, `.jar`, `.dex`, or `.apk` through a JVM/Android backend: CFR, Vineflower, Procyon, JADX, and others. `disrobe` validates the classfile itself (format 1.0.2-25) and recovers records, sealed types, and pattern matching where the backend supports them, plus Kotlin and Scala idioms.

## Coverage and fidelity

### Classfile

The in-house classfile decompiler is gated against real `javac`: on the EdgeCases corpus, the asserted floor is <!-- m:jvm_per_method_count -->131 of 131<!-- /m --> decompiled methods (100%) recompiling error-free on JDK 25. Its emitted source carries enum types with their constant bodies, declaration and member annotations, enhanced-`for` loops over arrays and iterables, and multi-`catch` clauses, each recompile-checked on the same corpus (`foreach_multicatch_recovery.rs`). CI provisions a JDK so this gate runs there.

### Dalvik

The Dalvik lifter's recovered bodies are graded by the real JVM bytecode verifier rather than by the lifter's own output: a committed gate assembles the recovered classes from the committed dex corpus, loads them under `-Xverify:all`, and asserts that the recovered classes pass the verifier; <!-- m:dalvik_verifier_pct -->100%<!-- /m --> of verifier-presented classes pass (<!-- m:dalvik_verifier_count -->118 of 118<!-- /m -->, 0 lifter verify failures; the other <!-- m:dalvik_link_skipped_count -->37 of 155<!-- /m --> classes are link-skipped because they reference supertypes the harness does not bundle, Kotlin's Function1 among them, which is a test-harness limit and not a lifter defect). A live-range-splitting pass recovers method bodies whose registers carry conflicting JVM types across control-flow joins; 317 re-hosted bodies verify clean under the same gate. The committed-corpus verifier floor and the EdgeCases recompile floor are asserted by committed test gates.

The in-house Dalvik decompiler, the default for `disrobe jvm decompile` on `.dex` and `.apk`, is graded on the same corpus against the real `EdgeCases.java` source rather than its own output. A value computed in one basic block and consumed in another (an array length, or a wide argument to a call such as `Math.abs` or `charAt`) is materialized into a local at its real use site instead of being dropped across the block boundary, so all eight leaf methods reconstruct their call sites with full fidelity while every method's signature, control flow, and operators recover (`dalvik_decompile_oracle.rs`).

### Obfuscator reversal

`disrobe` reverses JVM obfuscators that the raw decompilers cannot (Zelix KlassMaster, Allatori, Stringer, DashO, and DexGuard control-flow obfuscation on the Android side) and replays ProGuard/R8 mapping files to restore original names. It detects <!-- m:jvm_families -->10<!-- /m --> obfuscator and protector families in total: ProGuard/R8, Zelix KlassMaster, Allatori, Stringer, DashO, DexGuard, BlackObfuscator, yGuard, SkidSuite2, and JBCO (the last three detect-only, identified by marker strings and, for JBCO, its `jsr`/`ret` control flow).

On the Android side it also fingerprints eight runtime application self-protection (RASP) vendors so an analyst knows what the app does at run time: Promon SHIELD, Guardsquare DexGuard RASP and ThreatCast, Appdome, OneSpan, Arxan/Digital.ai, Zimperium zShield, and Licel DexProtector. APK signatures are verified across schemes v1 (JAR) through v4.

String-encryption protectors are decrypted by emulating each class's decrypt method on the encrypted constants rather than by guessing a key, so Allatori and DashO style `decrypt(String)` and `decrypt(int, String)` routines are recovered statically. The evaluator runs `<clinit>` for a per-class static key, constructs the receiver and runs `<init>` for an instance decrypt keyed on a field, synthesizes the calling frame for a caller/stack-trace-keyed key, and covers the long-accumulator arithmetic, `getfield`/`putfield`, and `switch`-dispatched keystreams these routines emit, all under a hard step cap. ProGuard and R8 names are restored from a `mapping.txt` with `disrobe jvm decompile --mapping mapping.txt`, disambiguating overloaded methods by their descriptor argument count.

On the Android side, `disrobe` deflattens BlackObfuscator control-flow flattening: it recognizes the `String.hashCode()` keyed dispatcher, matches each block's `const-string` block-name to its switch case, and recovers the original linear block order, annotating the deflattened sequence directly in the decompiled output. Obfuscator-planted out-of-range exception-table entries are dropped before structuring so they cannot poison the control-flow graph, and `jsr`/`ret` subroutines are inlined into a linear stream.

DexGuard hides string constants in an encrypted static `String[]` decrypted at run time through `java.lang.reflect.Method.invoke` rather than a direct call. The key and ciphertext are present in the dex; only the dispatch is reflective. `disrobe` runs a constrained Dalvik register machine over the dex's own routine: it executes the class `<clinit>` to rebuild the encrypted table, then runs the `decrypt(int)` body for each index (read the table element, apply the per-char transform against the embedded key, rebuild the string) and emits the plaintext, with the `Class.getDeclaredMethod` + `Method.invoke` call sites resolved to their concrete target. `disrobe jvm decompile app.dex` surfaces the recovered strings and resolved sites in the manifest.

## Limits

- The Dalvik body figure measured on the gitignored real FOSS apks is a self-report, not verifier-attested. Across all three apks the lifter self-reports a lowered body for <!-- m:dalvik_body_frac -->82788 / 89516<!-- /m --> defined methods, <!-- m:dalvik_body_pct -->92.5%<!-- /m -->. That is the corpus total and not any single apk. The figure counts the lifter returning a body rather than a throw-stub, so it grades its own output. Those apks are gitignored, so neither figure below re-derives in CI.

Per apk, self-reported bodies over defined methods: transmissionic 26192 of 27805, rustdesk 29376 of 32410, enrecipes 27220 of 29301.

A separate and much smaller population is graded by the real JVM rather than self-reported. Of 82756 non-stub candidate bodies, a deterministic 100-permille sample takes 8343, and 2994 of those can be re-hosted into an isolated carrier. Of the ones presented, <!-- m:dalvik_body_attested_frac -->2960 of 2994<!-- /m --> pass `-Xverify:all`. The remaining 5349 are excluded by harness limits and are ungraded rather than passing: 1400 constructors, 1672 invokespecial receivers, 2128 unresolvable framework dependencies, and 149 others.

Per apk, attested bodies over bodies presented: transmissionic 980 of 993, rustdesk 1205 of 1216, enrecipes 775 of 785. Every attested and every rejected body is listed by name under `crates/disrobe-pass-jvm/tests/golden/dalvik_body_attest/`, so a body cannot start failing the verifier while the count stays flat.
- Runtime-keyed string schemes (system property, environment, clock, secure random, or a live cross-class table, as Stringer sometimes uses) are flagged as walled instead of faked.
- A DexGuard routine that derives its key from runtime-only state (a system property, the environment, the clock, or a secure random) is reported as runtime-keyed rather than guessed.
- Commercial DexGuard is paid Guardsquare software whose protected output is unsafe to build on an analysis box, so that path is validated against a benign sample that exhibits the same reflection-string-decryption technique. The sample is a hand-written `.java` compiled by real `javac` and dexed by real `d8`; the plaintext it is graded against is the stdout of the same program run under a real JVM, not a list written beside the fixture.
- yGuard, SkidSuite2, and JBCO are detect-only.
