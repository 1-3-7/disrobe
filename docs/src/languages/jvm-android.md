# JVM and Android

`disrobe` decompiles JVM classfiles and Android DEX through a unified command, adding protector analysis, ProGuard/R8 mapping reports, and chain auto-detection, with headless wrappers for FOSS decompilers selected by the format's default routing or `--backend`.

## At a glance

| Surface | Support |
|---|---|
| Inputs | `.class`, `.jar`, `.dex`, `.apk`, `.aab`; the classfile itself validated in-house (format 1.0.2-25) |
| Decompilers | In-house classfile and Dalvik decompilers, the Dalvik one default on `.dex` and `.apk`; CFR, Vineflower, Procyon, JADX, and others via `--backend` |
| Language surface | Records, sealed types, pattern matching, enum constant bodies, declaration and member annotations, enhanced `for`, multi-`catch`, plus Kotlin and Scala idioms |
| Obfuscator handling | String recovery for supported Zelix KlassMaster, Allatori, Stringer, and DashO patterns; DexGuard and BlackObfuscator control-flow analysis; ProGuard/R8 name reports from `mapping.txt` |
| Detection and routing roster (<!-- m:jvm_families -->10<!-- /m -->) | ProGuard/R8, Zelix KlassMaster, Allatori, Stringer, DashO, DexGuard, BlackObfuscator, yGuard, SkidSuite2, JBCO (the last three detect-only) |
| RASP vendors (<!-- m:rasp_vendors -->8<!-- /m -->) | Promon SHIELD, Guardsquare DexGuard RASP and ThreatCast, Appdome, OneSpan, Arxan/Digital.ai, Zimperium zShield, Licel DexProtector |
| Signatures | v1 signing-material inventory; v2, v3, and v3.1 content-digest verification; v4 `.idsig` parsing with APK-digest matching to v2 or v3 |

## Commands

```sh
disrobe jvm decompile App.class --emit source --out src/          # write the in-house Java source
disrobe jvm decompile app.jar --backend vineflower --out src/
disrobe jvm decompile app.apk --backend jadx --out src/
disrobe jvm decompile classes.dex --backend jadx --out src/
disrobe jvm decompile app.jar --mapping mapping.txt --out src/   # write name-restoration.json
disrobe jvm extract app.apk --out classes/    # extract a .jar / .apk + dump classfile inventory
disrobe jvm backends                          # report available JVM/Android backends on PATH
disrobe jvm jni app.apk                       # link native methods against the apk's own .so files
disrobe jvm jni App.class --native libnative.so --json
disrobe jvm jni module.aar                    # nested classes.jar against jni/<abi>/*.so
disrobe jvm jni base.apk --native split.apk    # cross-split link against an APK Set member
disrobe apk app.apk                           # also prints the JNI link table for the embedded dex/.so pair
disrobe auto app.apk --out recovered/         # recursively process recognized payloads
```

Backend routing differs by format. `.dex` and `.apk` write in-house Dalvik source by default and invoke an Android backend only when `--backend jadx` or `--backend dex2jar` is selected. `.jar` writes in-house per-class source by default, and `--backend auto` also invokes the first available JVM backend. `.class` uses `--backend auto` for the first available JVM backend; add `--emit source` to write the in-house source. `disrobe` validates the classfile itself (format 1.0.2-25) and recovers records, sealed types, and pattern matching where the selected backend supports them, plus Kotlin and Scala idioms.

## Coverage and fidelity

### Classfile

The in-house classfile decompiler is gated against real `javac`: on the EdgeCases corpus, the asserted floor is <!-- m:jvm_per_method_count -->131 of 131<!-- /m --> decompiled methods (100%) recompiling error-free on JDK 25. Its emitted source carries enum types with their constant bodies, declaration and member annotations, enhanced-`for` loops over arrays and iterables, and multi-`catch` clauses, each recompile-checked on the same corpus (`foreach_multicatch_recovery.rs`). CI provisions a JDK so this gate runs there.

### Dalvik

The Dalvik lifter's recovered bodies are graded by the real JVM bytecode verifier rather than by the lifter's own output: a committed gate assembles the recovered classes from the committed dex corpus, loads them under `-Xverify:all`, and asserts that the recovered classes pass the verifier; <!-- m:dalvik_verifier_pct -->100%<!-- /m --> of verifier-presented classes pass (<!-- m:dalvik_verifier_count -->118 of 118<!-- /m -->, 0 lifter verify failures; the other <!-- m:dalvik_link_skipped_count -->37 of 155<!-- /m --> classes are link-skipped because they reference supertypes the harness does not bundle, Kotlin's Function1 among them, which is a test-harness limit and not a lifter defect). A live-range-splitting pass recovers method bodies whose registers carry conflicting JVM types across control-flow joins; 317 re-hosted bodies verify clean under the same gate. The committed-corpus verifier floor and the EdgeCases recompile floor are asserted by committed test gates.

The in-house Dalvik decompiler, the default for `disrobe jvm decompile` on `.dex` and `.apk`, is graded on the same corpus against the real `EdgeCases.java` source rather than its own output. A value computed in one basic block and consumed in another (an array length, or a wide argument to a call such as `Math.abs` or `charAt`) is materialized into a local at its real use site instead of being dropped across the block boundary, so all eight leaf methods reconstruct their call sites with full fidelity while every method's signature, control flow, and operators recover (`dalvik_decompile_oracle.rs`).

The same source path reverses core-library desugaring emitted by D8 9.1.31 with `desugar_jdk_libs_configuration` 2.1.5. It restores marker-confirmed public API types in the `j$/time`, `j$/util`, and `j$/nio` namespaces, receiver-first `$-EL` calls, `$-CC` interface static calls, and exact supported `Desugar*` retarget helpers. The committed minimum-API-21 DEX covers time, streams, functions, `Optional`, concurrent, and NIO APIs. A minimum-API-34 DEX built from the same Java source provides the original call-shape reference. The test recompiles every recovered compilation unit with Java 11, then executes every recovered API probe method through an independent harness. Unknown configuration identifiers, application-owned `j$/` classes, wrapper conversions, API flips, unknown helpers, and malformed receiver shapes remain unreversed instead of being renamed by prefix.

### Obfuscator analysis and recovery

For JVM classfiles, `disrobe` peels supported protector string patterns before in-house source emission. On Dalvik, it analyzes DexGuard-style control-flow flattening and BlackObfuscator dispatchers. `--mapping` parses ProGuard/R8 mappings and writes recovered class and member names to `name-restoration.json`; it does not rewrite emitted Java source. `disrobe` registers detection and routing for <!-- m:jvm_families -->10<!-- /m --> obfuscator and protector families: ProGuard/R8, Zelix KlassMaster, Allatori, Stringer, DashO, DexGuard, BlackObfuscator, yGuard, SkidSuite2, and JBCO (the last three detect-only, identified by marker strings and, for JBCO, its `jsr`/`ret` control flow).

On the Android side it also applies eight runtime application self-protection (RASP) fingerprint rules: Promon SHIELD, Guardsquare DexGuard RASP and ThreatCast, Appdome, OneSpan, Arxan/Digital.ai, Zimperium zShield, and Licel DexProtector. For APK signatures, `disrobe` inventories v1 signing material, verifies v2, v3, and v3.1 content digests, and parses v4 `.idsig` files to match their APK digest to a computed v2 or v3 content digest.

String-encryption protectors are decrypted by emulating each class's decrypt method on the encrypted constants rather than by guessing a key, so Allatori and DashO style `decrypt(String)` and `decrypt(int, String)` routines are recovered statically. The evaluator runs `<clinit>` for a per-class static key, constructs the receiver and runs `<init>` for an instance decrypt keyed on a field, synthesizes the calling frame for a caller/stack-trace-keyed key, and covers the long-accumulator arithmetic, `getfield`/`putfield`, and `switch`-dispatched keystreams these routines emit, all under a hard step cap. With `disrobe jvm decompile --mapping mapping.txt`, ProGuard and R8 names are written to `name-restoration.json`, with overloaded methods disambiguated by descriptor argument count; emitted Java identifiers are unchanged.

On the Android side, the BlackObfuscator analyzer recognizes the `String.hashCode()` keyed dispatcher, matches each block's `const-string` block-name to its switch case, and reports the recovered linear block order in the decompiled output. The method body remains rendered from the flattened graph; the annotation records the recovered order rather than replacing that body. Separately, obfuscator-planted out-of-range exception-table entries are dropped before classfile structuring so they cannot poison the control-flow graph, and `jsr`/`ret` subroutines are inlined into a linear stream.

DexGuard hides string constants in an encrypted static `String[]` decrypted at run time through `java.lang.reflect.Method.invoke` rather than a direct call. The key and ciphertext are present in the dex; only the dispatch is reflective. `disrobe` runs a constrained Dalvik register machine over the dex's own routine: it executes the class `<clinit>` to rebuild the encrypted table, then runs the `decrypt(int)` body for each index (read the table element, apply the per-char transform against the embedded key, rebuild the string) and emits the plaintext, with the `Class.getDeclaredMethod` + `Method.invoke` call sites resolved to their concrete target. `disrobe jvm decompile app.dex` surfaces the recovered strings and resolved sites in the manifest.

### JNI linking

`disrobe jvm jni` and `disrobe apk` link each declared `native` method to its C implementation across the DEX/classfile-to-`.so`/`.dll`/`.dylib` boundary. Static binding computes both the short and the long JNI symbol from the class name, method name, and descriptor (`_`, `$`, `[`, and non-ASCII characters mangled per the JNI spec) and matches them against the library's exported symbols. A `RegisterNatives` call built at compile time is recovered directly from the library's read-only data: the tool walks candidate `JNINativeMethod` triples, applies ELF relocations to their pointer fields, and resolves the target function address to its symbol, including calls made indirectly through the `JNIEnv` function table. The output is the typed link table plus a `JNIEXPORT ... JNICALL` C prototype per native method, graded against `javac -h` and compiled against a real NDK `jni.h`. An APK or AAB whose zip carries both the DEX and the native library links them without the caller naming either side; `--native` supplies the library explicitly for a bare `.class`/`.jar`/`.dex` input, including a Windows `.dll` or a macOS `.dylib` for desktop JNI. An AAR unzips its nested `classes.jar` and scans `jni/<abi>/*.so` (the AAR convention, distinct from an APK's `lib/<abi>/`). An APK Set (`.apks`), or a base APK plus one or more split APKs passed via `--native`, merges every split's dex and native libraries into one input set, so a native method declared in the base dex can resolve against a symbol that exists only in a config split. A raw `.oat` file locates its single embedded dex through the OAT header's `oat_dex_files_offset`; a multi-dex `.oat` refuses rather than guesses the per-entry record stride, which is version-dependent and undocumented across ART releases. `disrobe auto` performs the same link and writes `jni-link.json` when both sides are present in one container.

A native method with no matching symbol in any library is reported unresolved rather than dropped. A symbol exported by more than one library is reported ambiguous rather than silently bound to the first. Each resolving library's ABI directory name is carried on its entry so a multi-ABI APK states which `.so` a symbol came from. A `JNINativeMethod` array the compiler placed in the library's read-only data recovers as a static triple; a table a program assembles in memory at run time leaves no trace in the file and is not statically recoverable, so that native reports as unresolved with `dynamic_only` counting it.

Only two things are absent from the static artifact and therefore unrecoverable: a `fnPtr` computed at runtime rather than stored as a relocatable pointer, and a `FindClass` target name built dynamically rather than passed as a string literal. The native function body at a recovered address is not this surface's job; it goes to the native pseudo-C decompiler.

## Limits

- The Dalvik body figure measured on the gitignored real FOSS apks is a self-report, not verifier-attested. Across all three apks the lifter self-reports a lowered body for <!-- m:dalvik_body_frac -->82923 / 89516<!-- /m --> defined methods, <!-- m:dalvik_body_pct -->92.6%<!-- /m -->. That is the corpus total and not any single apk. The figure counts the lifter returning a body rather than a throw-stub, so it grades its own output. Those apks are gitignored, so neither figure below re-derives in CI.

Per apk, self-reported bodies over defined methods: transmissionic 26224 of 27805, rustdesk 29423 of 32410, enrecipes 27276 of 29301.

A separate and much smaller population is graded by the real JVM rather than self-reported. Of 82891 non-stub candidate bodies, a deterministic 100-permille sample takes 8357, and 2990 of those can be re-hosted into an isolated carrier. Of the ones presented, <!-- m:dalvik_body_attested_frac -->2976 of 2990<!-- /m --> pass `-Xverify:all`. The remaining 5367 are excluded by harness limits and are ungraded rather than passing: 1402 constructors, 1678 invokespecial receivers, 2138 unresolvable framework dependencies, and 149 others.

Per apk, attested bodies over bodies presented: transmissionic 987 of 990, rustdesk 1211 of 1218, enrecipes 778 of 782. Every attested and every rejected body is listed by name under `crates/disrobe-pass-jvm/tests/golden/dalvik_body_attest/`, so a body cannot start failing the verifier while the count stays flat.
- Runtime-keyed string schemes (system property, environment, clock, secure random, or a live cross-class table, as Stringer sometimes uses) are flagged as walled instead of faked.
- A DexGuard routine that derives its key from runtime-only state (a system property, the environment, the clock, or a secure random) is reported as runtime-keyed rather than guessed.
- Commercial DexGuard is paid Guardsquare software whose protected output is unsafe to build on an analysis box, so that path is validated against a benign sample that exhibits the same reflection-string-decryption technique. The sample is a hand-written `.java` compiled by real `javac` and dexed by real `d8`; the plaintext it is graded against is the stdout of the same program run under a real JVM, not a list written beside the fixture.
- yGuard, SkidSuite2, and JBCO are detect-only.
