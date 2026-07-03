# JVM and Android

**disrobe** decompiles JVM classfiles and Android DEX through a unified command, wrapping the best FOSS decompilers headlessly while adding obfuscator reversal, ProGuard/R8 mapping replay, and chain auto-detection.

## Decompiling

```sh
disrobe jvm decompile App.class --out src/
disrobe jvm decompile app.jar --backend vineflower --out src/
disrobe jvm decompile app.apk --backend jadx --out src/
disrobe jvm decompile classes.dex --backend jadx --out src/
```

Routes a `.class`, `.jar`, `.dex`, or `.apk` through a JVM/Android backend: CFR, Vineflower, Procyon, JADX, and others. **disrobe** validates the classfile itself (format 1.0.2-25) and recovers records, sealed types, and pattern matching where the backend supports them, plus Kotlin and Scala idioms.

## Fidelity

The in-house classfile decompiler is gated against real `javac`: on the EdgeCases corpus, the asserted floor is 131 of 131 decompiled methods (100%) recompiling error-free on JDK 25. CI provisions a JDK so this gate runs there. The Dalvik lifter's recovered bodies are graded by the real JVM bytecode verifier rather than by the lifter's own output: a committed gate assembles the recovered classes from the committed dex corpus, loads them under `-Xverify:all`, and asserts that the recovered classes pass the verifier; 99% of verifiable classes pass (102 of 103, 0 lifter verify failures; the 103rd is link-blocked by an unbundled Kotlin Function1 supertype, a test-harness limit not a lifter defect). On the gitignored real FOSS apks the lifter self-reports a lowered body for 89% to 92.5% of methods (transmissionic 92.5%, enrecipes 90.7%, rustdesk 89.0%), but that figure counts the lifter returning a body rather than a throw-stub and is not verifier-attested; those apks cannot run in CI. A live-range-splitting pass recovers method bodies whose registers carry conflicting JVM types across control-flow joins; 307 re-hosted bodies verify clean under the same gate. The committed-corpus verifier floor and the EdgeCases recompile floor are asserted by committed test gates.

## Inventory and backends

```sh
disrobe jvm extract app.apk --out classes/    # extract a .jar / .apk + dump classfile inventory
disrobe jvm backends                          # report available JVM/Android backends on PATH
```

## Obfuscator reversal

**disrobe** reverses JVM obfuscators that the raw decompilers cannot (Zelix KlassMaster, Allatori, Stringer, DashO, and DexGuard control-flow obfuscation on the Android side) and replays ProGuard/R8 mapping files to restore original names. It detects nine obfuscator and protector families in total: ProGuard/R8, Zelix KlassMaster, Allatori, Stringer, DashO, DexGuard, yGuard, SkidSuite2, and JBCO (the last three detect-only, identified by marker strings and, for JBCO, its `jsr`/`ret` control flow).

On the Android side it also fingerprints eight runtime application self-protection (RASP) vendors so an analyst knows what the app does at run time: Promon SHIELD, Guardsquare DexGuard RASP and ThreatCast, Appdome, OneSpan, Arxan/Digital.ai, Zimperium zShield, and Licel DexProtector. APK signatures are verified across schemes v1 (JAR) through v4.

String-encryption protectors are decrypted by emulating each class's decrypt method on the encrypted constants rather than by guessing a key, so Allatori and DashO style `decrypt(String)` and `decrypt(int, String)` routines are recovered statically. The evaluator runs `<clinit>` for a per-class static key, constructs the receiver and runs `<init>` for an instance decrypt keyed on a field, synthesizes the calling frame for a caller/stack-trace-keyed key, and covers the long-accumulator arithmetic, `getfield`/`putfield`, and `switch`-dispatched keystreams these routines emit, all under a hard step cap. Runtime-keyed schemes (system property, environment, clock, secure random, or a live cross-class table, as Stringer sometimes uses) are flagged as walled instead of faked. ProGuard and R8 names are restored from a `mapping.txt` with `disrobe jvm decompile --mapping mapping.txt`, disambiguating overloaded methods by their descriptor argument count.

On the Android side, **disrobe** deflattens BlackObfuscator control-flow flattening: it recognizes the `String.hashCode()` keyed dispatcher, matches each block's `const-string` block-name to its switch case, and recovers the original linear block order, annotating the deflattened sequence directly in the decompiled output. Obfuscator-planted out-of-range exception-table entries are dropped before structuring so they cannot poison the control-flow graph, and `jsr`/`ret` subroutines are inlined into a linear stream.

DexGuard hides string constants in an encrypted static `String[]` decrypted at run time through `java.lang.reflect.Method.invoke` rather than a direct call. The key and ciphertext are present in the dex; only the dispatch is reflective. **disrobe** runs a constrained Dalvik register machine over the dex's own routine: it executes the class `<clinit>` to rebuild the encrypted table, then runs the `decrypt(int)` body for each index (read the table element, apply the per-char transform against the embedded key, rebuild the string) and emits the plaintext, with the `Class.getDeclaredMethod` + `Method.invoke` call sites resolved to their concrete target. `disrobe jvm decompile app.dex` surfaces the recovered strings and resolved sites in the manifest. A routine that derives its key from runtime-only state (a system property, the environment, the clock, or a secure random) is reported as runtime-keyed rather than guessed. Commercial DexGuard is paid Guardsquare software whose protected output is unsafe to build on an analysis box, so this path is validated against a self-authored benign dex that exhibits the same reflection-string-decryption technique, graded against its authored plaintext.

## Chaining

```sh
disrobe auto app.apk --out recovered/    # APK -> dex -> JADX + Smali + manifest
```
