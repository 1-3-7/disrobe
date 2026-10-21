# JVM and Android

`disrobe` decompiles JVM classfiles and Android DEX through a unified command, adding protector analysis, ProGuard/R8 mapping reports, and chain auto-detection, with headless wrappers for FOSS decompilers selected by the format's default routing or `--backend`.

## At a glance

| Surface | Support |
|---|---|
| Inputs | `.class`, `.jar`, `.dex`, `.apk`, `.aab`; ODEX, single-DEX OAT, JDK `.jmod` and `lib/modules` jimage containers; the classfile itself validated in-house (format 1.0.2-25) |
| Decompilers | In-house classfile and Dalvik decompilers, the Dalvik one default on `.dex` and `.apk`; CFR, Vineflower, Procyon, JADX, and others via `--backend` |
| Language surface | Records, sealed types, pattern matching, enum constant bodies, declaration and member annotations, enhanced `for`, multi-`catch`, plus Kotlin and Scala idioms |
| Obfuscator handling | String recovery for supported Zelix KlassMaster, Allatori, Stringer, and DashO patterns; JBCO and Skidfuscator flow obfuscation folded before structuring; DexGuard and BlackObfuscator control-flow analysis; ProGuard/R8 name reports from `mapping.txt` |
| Detection and routing roster (<!-- m:jvm_families -->10<!-- /m -->) | ProGuard/R8, Zelix KlassMaster, Allatori, Stringer, DashO, DexGuard, BlackObfuscator, yGuard, SkidSuite2, JBCO (the last three have no protector-specific pass) |
| RASP vendors (<!-- m:rasp_vendors -->8<!-- /m -->) | Promon SHIELD, Guardsquare DexGuard RASP and ThreatCast, Appdome, OneSpan, Arxan/Digital.ai, Zimperium zShield, Licel DexProtector. No command runs this detector yet; `behavior` and `auto` report the runtime markers of Promon, Appdome, Zimperium, Guardsquare, and DexProtector |
| Signatures | v1 signing-material inventory; v2, v3, and v3.1 content-digest verification; v4 `.idsig` parsing with APK-digest matching to v2 or v3 |

## Commands

```sh
disrobe jvm decompile App.class --emit source --out src/          # write the in-house Java source
disrobe jvm decompile app.jar --backend vineflower --out src/
disrobe jvm dex2-jar classes.dex --out classes/  # in-house .class tree + classes.jar
disrobe jvm decompile classes.dex --backend dex2-jar --out external/  # installed d2j-dex2jar
disrobe jvm decompile app.apk --backend jadx --out src/
disrobe jvm decompile classes.dex --backend jadx --out src/
disrobe jvm decompile classes.dex --format ghidra --out recovered/
disrobe jvm decompile app.jar --mapping mapping.txt --out src/   # write name-restoration.json
disrobe jvm extract app.apk --out classes/    # extract a .jar / .apk + dump classfile inventory
disrobe jvm backends                          # report available JVM/Android backends on PATH
disrobe jvm jni app.apk                       # link native methods against the apk's own .so files
disrobe jvm jni App.class --native libnative.so --json
disrobe jvm jni module.aar                    # nested classes.jar against jni/<abi>/*.so
disrobe jvm jni base.apk --native split.apk    # cross-split link against an APK Set member
disrobe apk app.apk                           # resources, certificates, the JNI link table and the code-pattern audit
disrobe auto app.apk --out recovered/         # recursively process recognized payloads
disrobe auto classes.dex --format json --out recovered/
```

Every format writes in-house source by default: Dalvik source for `.dex` and `.apk`, per-class source for `.jar` and `.class`. An external backend runs only when `--backend` names it: `cfr`, `vineflower`, `procyon`, `jd` or `krakatau` for class and jar files, `jadx` or `dex2-jar` for DEX and APK input. A named backend that is not installed, or that does not apply to the input format, fails with an error. `disrobe` validates the classfile itself (format 1.0.2-25) and recovers records, sealed types, and pattern matching where the selected backend supports them, plus Kotlin and Scala idioms.

`disrobe jvm dex2-jar` is the in-house DEX-to-class translator. It writes a deterministic class tree and `classes.jar` without an external executable. `disrobe jvm decompile <dex> --backend dex2-jar` is different: it invokes an installed `d2j-dex2jar` backend and keeps that backend's contract and output separate from the in-house translator.

The in-house translator carries `InnerClasses`, `EnclosingMethod`, and generic `Signature` attributes from DEX system annotations. The Dalvik renderer uses ownership metadata to group nested classes; a `$` in a name alone does not establish nesting. Invalid annotation metadata is reported without rejecting an otherwise parseable DEX.

For a standalone DEX, `jvm decompile --format ghidra|ida|json` writes descriptor-keyed class, method, and field entries beside the normal output. `auto` accepts the same formats when the original input itself reaches a successful `jvm.classify` node and writes the sidecar under `exports/dalvik/`. It does not reuse a DEX extracted from an APK or another container. Each entry keeps the original owner, original member name, descriptor, and replacement as separate values. When the current recovery path has not changed a name, the original and replacement stay identical. The Ghidra and IDAPython scripts resolve the original logical identity in the loaded DEX database before renaming the database object; they do not assign virtual addresses to Dalvik identifiers. IDAPython class renames require IDA 9.4 or later because that release introduced the loader's persistent DEX type-rename store. Method and field renames use the older DEX record APIs.

## Coverage and fidelity

### Classfile

The in-house classfile decompiler is gated against real `javac`: on the EdgeCases corpus, the asserted floor is <!-- m:jvm_per_method_count -->131 of 131<!-- /m --> decompiled methods (100%) recompiling error-free on JDK 25. Its emitted source carries enum types with their constant bodies, declaration and member annotations, enhanced-`for` loops over arrays and iterables, and multi-`catch` clauses, each recompile-checked on the same corpus (`foreach_multicatch_recovery.rs`). CI provisions a JDK so this gate runs there.

### Dalvik

The Dalvik lifter's recovered bodies are graded by the real JVM bytecode verifier rather than by the lifter's own output: a committed gate assembles the recovered classes from the committed dex corpus, loads them under `-Xverify:all`, and asserts that the recovered classes pass the verifier; <!-- m:dalvik_verifier_pct -->100%<!-- /m --> of verifier-presented classes pass (<!-- m:dalvik_verifier_count -->118 of 118<!-- /m -->, 0 lifter verify failures; the other <!-- m:dalvik_link_skipped_count -->37 of 155<!-- /m --> classes are link-skipped because they reference supertypes the harness does not bundle, Kotlin's Function1 among them, which is a test-harness limit and not a lifter defect). A live-range-splitting pass recovers method bodies whose registers carry conflicting JVM types across control-flow joins; 317 re-hosted bodies verify clean under the same gate. The committed-corpus verifier floor and the EdgeCases recompile floor are asserted by committed test gates.

The in-house Dalvik decompiler, the default for `disrobe jvm decompile` on `.dex` and `.apk`, is graded on the same corpus against the real `EdgeCases.java` source rather than its own output. A value computed in one basic block and consumed in another (an array length, or a wide argument to a call such as `Math.abs` or `charAt`) is materialized into a local at its real use site instead of being dropped across the block boundary, so all eight leaf methods reconstruct their call sites with full fidelity while every method's signature, control flow, and operators recover (`dalvik_decompile_oracle.rs`).

The same source path reverses core-library desugaring emitted by D8 9.1.31 with `desugar_jdk_libs_configuration` 2.1.5. It restores marker-confirmed public API types in the `j$/time`, `j$/util`, and `j$/nio` namespaces, receiver-first `$-EL` calls, `$-CC` interface static calls, and exact supported `Desugar*` retarget helpers. The committed minimum-API-21 DEX covers time, streams, functions, `Optional`, concurrent, and NIO APIs. A minimum-API-34 DEX built from the same Java source provides the original call-shape reference. The test recompiles every recovered compilation unit with Java 11, then executes every recovered API probe method through an independent harness. Unknown configuration identifiers, application-owned `j$/` classes, wrapper conversions, API flips, unknown helpers, and malformed receiver shapes remain unreversed instead of being renamed by prefix.

### Containers

`auto` opens four container formats and passes their members to the class and DEX passes. An ODEX yields its embedded `classes.dex`. An OAT file yields its single DEX, found through the `oatdata` symbol and the OAT header; when the DEX lives in a separate `.vdex`, which is the usual layout on current ART, the OAT file yields only its manifest and a refusal, because VDEX is not read. A `.jmod` yields every entry at its archive path, and a jimage (`lib/modules`) yields every stored resource as `module/parent/name`; compressed jimage resources are refused rather than emitted, because no jimage decompressor is implemented. Each container also writes `jvm-container.json`. The jmod reader shares the zip limits (65,536 entries, 256 MiB per entry, 1 GiB in total) and the jimage reader enforces the same totals. `tests/jvm_container_chain.rs` grades a committed jmod against `jmod extract` and the grading JDK's own `lib/modules` against `jimage extract`, byte for byte.

### Obfuscator analysis and recovery

For JVM classfiles, `disrobe` peels supported protector string patterns before in-house source emission. On Dalvik, it lifts a DexGuard-style flattened method from the rewired control-flow graph when every dispatcher edge resolves to a constant successor and the state register is read only by its dispatcher; otherwise the method keeps a note naming why it was not rewired. BlackObfuscator dispatchers are analyzed. `--mapping` parses ProGuard/R8 mappings and writes recovered class and member names to `name-restoration.json`; it does not rewrite emitted Java source. `disrobe` registers detection and routing for <!-- m:jvm_families -->10<!-- /m --> obfuscator and protector families: ProGuard/R8, Zelix KlassMaster, Allatori, Stringer, DashO, DexGuard, BlackObfuscator, yGuard, SkidSuite2, and JBCO (the last three identified by marker strings and, for JBCO, its `jsr`/`ret` control flow, with no protector-specific pass).

Flow obfuscation is folded before structuring. A method qualifies when its class tests a static `Boolean` it only ever initializes to a constant (the opaque predicate JBCO plants), when it contains unreachable code or a typed handler that only rethrows, or when a branch depends on a static `int` function of constants (the per-block seeds Skidfuscator advances through hash functions). For such a method `disrobe` runs a bounded constant-flow analysis: it evaluates the pure static `int` functions of the classes it was given and `Integer.parseInt` of decimal constants, folds every branch and switch whose operands it decides, removes typed handlers that only rethrow what they caught, turns an exception allocated and thrown only to reach its own handler into a jump, and drops the code left unreachable. Catch-all handlers, which `javac` emits for `finally`, are kept, and a method that reads a local it never assigns is left as it is.

On the Android side it also applies eight runtime application self-protection (RASP) fingerprint rules: Promon SHIELD, Guardsquare DexGuard RASP and ThreatCast, Appdome, OneSpan, Arxan/Digital.ai, Zimperium zShield, and Licel DexProtector. For APK signatures, `disrobe` inventories v1 signing material, verifies v2, v3, and v3.1 content digests, and parses v4 `.idsig` files to match their APK digest to a computed v2 or v3 content digest.

String-encryption protectors are decrypted by emulating each class's decrypt method on the encrypted constants rather than by guessing a key, so Allatori and DashO style `decrypt(String)` and `decrypt(int, String)` routines are recovered statically. The evaluator runs `<clinit>` for a per-class static key, constructs the receiver and runs `<init>` for an instance decrypt keyed on a field, synthesizes the calling frame for a caller/stack-trace-keyed key, and covers the long-accumulator arithmetic, `getfield`/`putfield`, and `switch`-dispatched keystreams these routines emit, all under a hard step cap. With `disrobe jvm decompile --mapping mapping.txt`, ProGuard and R8 names are written to `name-restoration.json`, with overloaded methods disambiguated by descriptor argument count; emitted Java identifiers are unchanged.

On the Android side, the BlackObfuscator analyzer recognizes the `String.hashCode()` keyed dispatcher, matches each block's `const-string` block-name to its switch case, and reports the recovered linear block order in the decompiled output. The method body remains rendered from the flattened graph; the annotation records the recovered order rather than replacing that body. Separately, obfuscator-planted out-of-range exception-table entries are dropped before classfile structuring so they cannot poison the control-flow graph, and `jsr`/`ret` subroutines are inlined into a linear stream.

DexGuard hides string constants in an encrypted static `String[]` decrypted at run time through `java.lang.reflect.Method.invoke` rather than a direct call. The key and ciphertext are present in the dex; only the dispatch is reflective. `disrobe` runs a constrained Dalvik register machine over the dex's own routine: it executes the class `<clinit>` to rebuild the encrypted table, then runs the `decrypt(int)` body for each index (read the table element, apply the per-char transform against the embedded key, rebuild the string) and emits the plaintext, with the `Class.getDeclaredMethod` + `Method.invoke` call sites resolved to their concrete target. `disrobe jvm decompile app.dex` surfaces the recovered strings and resolved sites in the manifest.

### Identification

`disrobe identify` recognises APK, DEX, JAR and class inputs before the native identifier runs and reports, with evidence and a confidence, the DEX version and Android range, the DEX writer (`d8/r8` when the data section carries code items, debug info, type lists and string data first and the map list last, the layout those writers produce; any other layout is reported as an unknown writer rather than guessed), ProGuard or R8 renaming (at least half of the top-level classes carry one- or two-letter names), the protector catalog matches on class files (Allatori, DashO, Zelix KlassMaster, Stringer, yGuard, SkidSuite2, JBCO), RASP vendors and the stub-loader packing scheme on APKs, commercial packer anchors from the mobile pass, the APK signature schemes with their verification result, and the anti-analysis checks the code-pattern audit anchors (debugger, emulator and root checks, dynamic code loading). `tests/android_identify.rs` grades the d8-built fixtures, the R8-minified and clean pair, the plant and control APKs and an Allatori class; a zip without a manifest, DEX or class files is not claimed.

### APK resources and manifest

`disrobe apk` decodes the binary `AndroidManifest.xml` and `resources.arsc` in-house: the element tree with typed attribute values (references, strings, integers, booleans, hex, dimensions, fractions and colours), the resource table with ids, names and one value per configuration, and reconstructed `R.txt`, `R.java` and `values.xml`. `tests/formats/aapt2_dump_parity.rs` grades both decoders against committed `aapt2 dump xmltree` and `aapt2 dump resources` output (`corpus/apk/aapt2/`, build-tools 36.1) for the two aapt2-linked fixtures: every element, attribute and typed value of the manifests and every resource id, name and per-configuration value must be equal, and a control that changes one value in a dump turns the comparison red. Dimensions print as aapt2 does (`16dp`, `22sp`), strings and file resources resolve through the global string pool, and an `id` resource is the boolean `false` aapt2 prints as `(id)`.

The same command derives manifest facts from the decoded tree and prints them under `facts`, `permissions` and `components` (JSON key `manifest`): package, version code and name, compile, minimum and target SDK, used and declared permissions, `debuggable`, `allowBackup`, `usesCleartextTraffic` and `networkSecurityConfig`, and every activity, activity alias, service, receiver and provider with its qualified name, the explicit `exported` value, the effective exported state (an unset value is exported when the component declares an intent filter, and a provider without one is exported below SDK 17), its intent-filter count, launcher status, permission and authorities. The badging rows of the same test compare package, versions, SDK levels, permissions, the debuggable flag and the launchable activities with `aapt2 dump badging`.

### JNI linking

`disrobe jvm jni` and `disrobe apk` link each declared `native` method to its C implementation across the DEX or classfile to native library boundary. Static binding computes the short and the long JNI symbol from the class name, method name, and descriptor, escaping `_`, `;`, `[`, `$`, and non-ASCII characters as the JNI specification requires, and matches both against the library's exported symbols. A `JNINativeMethod` array that the compiler placed in the library's read-only data is recovered from the file: the tool walks candidate name, signature, and `fnPtr` triples, applies the ELF dynamic relocations to their pointer fields, and resolves each function address to its symbol. It reads the table, not the `RegisterNatives` call, so the recovery does not depend on how the call reaches the `JNIEnv` function table, and it finds no table that the program assembles in memory at run time. The output is the typed link table plus a `JNIEXPORT ... JNICALL` C prototype per native method.

An APK whose zip carries both the DEX and the native library links them without the caller naming either side; `--native` supplies the library for a bare `.class`, `.jar`, or `.dex` input. An AAR unzips its nested `classes.jar` and scans `jni/<abi>/*.so`, the AAR layout, rather than an APK's `lib/<abi>/`. An APK Set (`.apks`), or a base APK plus split APKs passed with `--native`, merges every split's DEX and native libraries into one input set, so a native method declared in the base DEX can resolve against a symbol that exists only in a config split. A raw `.oat` file locates its single embedded DEX through the OAT header's `oat_dex_files_offset`; a multi-dex `.oat` is refused, because the per-entry record stride changes between ART releases and is not documented. `disrobe auto` performs the same link and writes `jni-link.json` when both sides are in one container.

A native method with no matching symbol in any library is reported unresolved rather than dropped, and `dynamic_only` counts it. A symbol exported by more than one library is reported ambiguous rather than bound to the first. Each resolving library's ABI directory name is carried on its entry, so a multi-ABI APK states which `.so` a symbol came from.

The tests below run in `cargo xtask prepush` when `disrobe-pass-jvm` or `disrobe-cli` changes, and in the weekly scheduled CI run on Linux, macOS, and Windows; no JNI test runs on every push. "Real" means the input came from a real compiler or tool; "synthetic" means the test built the bytes itself.

| Behaviour | Test | Reference | Input |
|---|---|---|---|
| Short and long symbols, and the C prototypes | `jni_prototype_oracle.rs` | The header `javac -h` writes for a class with 28 native methods (overloads, `_`, `$`, a non-ASCII name, primitive, array, and reference types); the prototypes must also pass `-fsyntax-only` against the JDK's own `jni.h` | real `javac` output |
| `[` in a long symbol | unit test in `jni.rs` | A string written from the JNI specification; the `javac -h` fixture has no overloaded method with an array parameter | synthetic |
| Symbols for DEX methods | `jni_native_surface.rs` | Strings written to match `javac -h` | synthetic DEX and `.so` |
| `JNINativeMethod` recovery from read-only data | `jni_register_natives.rs` | `readelf` symbol values for the four registered functions, one reached through an `R_X86_64_RELATIVE` relocation | real x86-64 and AArch64 `.so` compiled from a committed C file that never calls `RegisterNatives` |
| APK linked by `disrobe auto`, `jni-link.json` | `auto_apk_dex.rs` | The four entries of the committed `.so` | a test-built APK holding the committed `Hello.dex` and `.so` |
| AAR | `jvm_jni_link.rs` | One static and four registered natives, both ABI directories named | a committed AAR: a `javac`-built `classes.jar`, one synthetic `.so`, and the committed x86-64 `.so` |
| JAR with `--native` | `jvm_jni_link.rs` | The four registered natives | the committed JAR and `.so` |
| APK Set, base plus split APK | `jvm_jni_link.rs` | One native resolved only by the split's symbol | synthetic |
| Single-dex `.oat` | `jvm_jni_link.rs`; unit tests in `oat.rs` for the multi-dex refusal | One native resolved | synthetic OAT headers, no `dex2oat` output |
| Unresolved natives | `jvm_jni_link.rs`, `jni_native_surface.rs` | Named in the text and JSON output with a count | synthetic DEX |
| A `d8`-built DEX against a `clang`-built `.so` | `jvm_jni_link.rs` | At least one native resolved | real `javac`, `d8`, and host `clang` output; the test prints `UNGRADED` and passes when `d8` is not on `PATH`, which is the case in CI |

Not graded by any test: AAB input, a Windows `.dll` or macOS `.dylib` passed with `--native`, the JNI table that `disrobe apk` prints, ambiguous symbols, a real `dex2oat` `.oat`, and an NDK-built library or the NDK's `jni.h`.

Only two things are absent from the static artifact and therefore unrecoverable: a `fnPtr` computed at runtime rather than stored as a relocatable pointer, and a `FindClass` target name built dynamically rather than passed as a string literal. The native function body at a recovered address is not this surface's job; it goes to the native pseudo-C decompiler.

### Code-pattern audit

`disrobe apk` audits every DEX in the package for insecure API use and reports each site as a `DR-APK-*` finding anchored to the class, method and instruction offset, with the resolved argument as evidence. The rules are evaluated on the bytecode, not on decompiled text: a `Cipher.getInstance` call is graded by the transformation string that reaches its argument register, a `SecretKeySpec` by whether its key bytes came from a string literal, a storage call by the mode constant it receives, and a `WebSettings` setter by the boolean it is passed. Eight categories are covered.

| Category | Rules |
|---|---|
| Weak cryptography | DES, 3DES, RC2, RC4 and Blowfish ciphers; ECB mode and bare `AES`; RSA without OAEP; MD2, MD4, MD5 and SHA-1 digests; `SecureRandom` seeded with a constant; `java.util.Random` feeding key material; keys and IVs built from string literals |
| Transport security | empty `X509TrustManager` checks and a null `getAcceptedIssuers`; a `HostnameVerifier` that returns `true`; the Apache `ALLOW_ALL_HOSTNAME_VERIFIER`; `SslErrorHandler.proceed`; `SSLContext` on SSL, SSLv3, TLSv1 or TLSv1.1 |
| Insecure storage | world-readable or world-writable file, preference, database and directory modes; external storage directories and literal `/sdcard` paths; temporary files; `execSQL` and `rawQuery` with a statement that is not a literal |
| WebView | JavaScript enabled, file and content access from file URLs, mixed content always allowed, saved passwords, `addJavascriptInterface`, remote debugging |
| Logging | every `android.util.Log` call, raised when a literal in the message mentions a password, token, secret, key or credential |
| Dangerous APIs | `Runtime.exec` and `ProcessBuilder`; `DexClassLoader`, `PathClassLoader` and in-memory class loaders; `System.load` by path; `Method.invoke` |
| Privacy | IMEI, MEID, IMSI, SIM serial, line number, `ANDROID_ID` and `Build.SERIAL`; SMS sending; clipboard reads; microphone, camera and location access; installed package enumeration |
| Anti-analysis | `su` execution and root-indicator paths and packages; emulator fingerprints compared against `Build` properties; `Debug.isDebuggerConnected` |

The grader is the authored `corpus/recon/android-audit` pair: a plant APK with one insecure use per method and a control APK that uses the same API families correctly, both built by `javac`, `d8`, `aapt2` and `apksigner` from committed sources. The test requires every plant to be reported at its own method and nothing else, and no finding on the control. Register values are tracked linearly within a method, so an argument that reaches the call through a branch merge is reported only when the literal is still the last write to that register; a transformation or mode computed at run time is not reported.

## Limits

Disrobe reports lowering <!-- m:dalvik_body_frac -->83662 / 83943<!-- /m --> methods with code items across three SHA-256-pinned FOSS APKs, or <!-- m:dalvik_body_pct -->99.7%<!-- /m -->. This counts emitted bodies. The APKs contain 89,516 declared methods, including 5,573 abstract, native, and interface-instance declarations without bodies.

The JVM check selects non-stub methods by a deterministic hash of each method name and re-hosts their bodies in isolated carriers. Of the bodies presented, <!-- m:dalvik_body_attested_frac -->2988 of 2998<!-- /m --> pass `-Xverify:all` without being invoked. Another 5,421 sampled bodies are ungraded: 1,407 constructors, 1,730 invokespecial receivers, 2,141 unresolved dependencies, and 143 other exclusions. The recovery chart's data records the full candidate and sample populations.

| APK | Emitted bodies / methods with code | JVM accepted / presented |
| --- | ---: | ---: |
| Transmissionic | 26,360 / 26,416 | 988 / 989 |
| RustDesk | 29,841 / 29,983 | 1,217 / 1,223 |
| EnRecipes | 27,461 / 27,544 | 783 / 786 |

The two `measureContentWidth` bodies excluded by the sampling rules are ungraded and do not contribute to the accepted count. Verdicts are pinned by method name under `crates/disrobe-pass-jvm/tests/golden/dalvik_body_attest/`. These measurements use local APKs; CI checks the published counts and the separate committed-DEX corpus.

- Runtime-keyed string schemes (system property, environment, clock, secure random, or a live cross-class table, as Stringer sometimes uses) are flagged as walled instead of faked.
- A DexGuard routine that derives its key from runtime-only state (a system property, the environment, the clock, or a secure random) is reported as runtime-keyed rather than guessed.
- DexGuard-style reflection-string recovery is validated against a benign sample implementing that technique, not output produced by the commercial DexGuard tool. The sample is a hand-written `.java` compiled by real `javac` and dexed by real `d8`; the plaintext reference is the stdout of the same program run under a real JVM.
- SkidSuite2 is detect-only. The [strict re-execution grader](../../../crates/disrobe-pass-jvm/tests/protectors/obfuscator_reexec_strict.rs) recompiles recovered Java with `javac`, runs it, and compares stdout and exit code with the clean program. It pins 28 obfuscated programs as fully recovered. Of these, 27 are real tool outputs: the five Soot 4.7.1 JBCO runner outputs, seven yGuard 5.0.0 outputs with their rename logs reversed into the original identifiers, four Skidfuscator outputs, nine ProGuard 7.10.0 runner outputs, and the ProGuard 7.9.1 and R8 9.1.31 `Hello` jars with their mappings applied. The 28th is an authored class in the classic Stringer string-encryption shape. Three fixtures stay named residuals. In the R8 `EdgeCases` jar, six try-with-resources and `finally` handlers that R8 reshaped into shared handler code form no foldable chain, and four pattern switches keep their `typeSwitch` call sites. The ProGuard `EdgeCases` jar also keeps its records' `toString`, `hashCode` and `equals` as `ObjectMethods` call sites, and that build throws at run time because the optimizer pruned an enum constant array. The Allatori caller-keyed pair decrypts through `swap` and `dup_x2` stack shuffles the lifter does not render. Four JBCO runner invocations failed in the tool and produced no fixtures. The Kotlin `EdgeCasesKt` jars from ProGuard and R8 are not graded, because their reference program needs `kotlinx-coroutines`, which no grader environment provides. The grader recovers each jar as one class set with its mapping or rename log applied. `disrobe jvm decompile` decompiles each class on its own, folding only the hash functions a class declares itself, so Skidfuscator dispatch that calls a sibling class stays in place there. Given `--mapping <mapping.txt>` or `--yguard-log <renamelog.xml>`, it also recovers the jar as one class set with the names restored, writes the Java under `recovered/`, and summarises the renames and any fallback methods in `source-recovery.json`.
