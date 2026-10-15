# Mobile (Hermes / Flutter)

`disrobe` detects the runtime inside a mobile package, extracts React Native and other bundles, decompiles Hermes bytecode to runnable JavaScript, and recovers Dart source or disassembles the ARM64 AOT snapshot from Flutter artifacts.

## At a glance

| Layer | Coverage |
|---|---|
| Runtimes detected | `react-native-apk`, `react-native-ipa`, `hermes-raw-bytecode`, `flutter-libapp-so`, `flutter-dart-kernel`, `xamarin-apk`, `cordova-apk`, `capacitor-apk`, `nativescript-apk`, `ipa`, `android-apk-dex`, `unknown` |
| Hermes | Bytecode versions v60 through v96, plus v98 and v99 (the Hermes compiler that React Native 0.84 and later ships), parse against the documented header layout; v62, v71, v74, v76, v83, v84, v85, v89, v90, v94, v96, v98, and v99 decompile to JavaScript. On v89, fifteen authored programs compiled by the real Hermes compiler decompile to scripts that print exactly what the Hermes interpreter printed; the same programs compiled by the compilers React Native 0.69, 0.71, and 0.72 ship (v85, v90, v94) do the same and disassemble to exactly what each compiler prints; the same fifteen, the authored sample, and a classes-and-private-fields program, compiled by the v98 and v99 compilers, decompile to scripts that print what their sources print |
| Dart kernel | `.dill` / `kernel_blob.bin` parsed to byte-exact original Dart bodies from the kernel source table |
| Dart AOT | `libapp.so` AArch64 bodies disassembled with resolved direct-call and branch targets, plus class table, library URIs, and string pool |
| Dart AOT declaration graph | full library/class/method/field inventory, with method parameter counts, from a `libapp.so` or four standalone snapshot blobs built by Dart 3.3 to 3.11, 3.12.1 or 3.12.2 (Flutter 3.19 to 3.44) for Android arm64 |
| Rename maps | Flutter `obfuscation_map.json` parsed into a typed original-to-obfuscated lookup |

## Commands

```sh
disrobe mobile detect app.apk
disrobe mobile extract app.apk --out bundles/
disrobe mobile hermes index.android.bundle --out disasm/
disrobe mobile flutter libapp.so --out layout.json

disrobe hermes decompile index.android.bundle --out surface/
disrobe hermes disasm index.android.bundle --out disasm/
disrobe hermes info index.android.bundle

disrobe flutter dump libapp.so --out layout.json
disrobe flutter dump libflutter.so --format json --engine-symbol-map engine-symbols.json
disrobe flutter decompile libapp.so --out estimate.json
disrobe flutter kernel app.dill --out kernel.json
disrobe flutter disasm libapp.so --emit-listing
disrobe flutter map obfuscation_map.json --out map.json
disrobe flutter inventory libapp.so --out inventory.json
disrobe flutter inventory-standalone vm_data vm_instructions isolate_data isolate_instructions --out inventory.json
disrobe flutter identity app.apk
```

`mobile detect` classifies the package; `mobile extract` pulls bundles out of the container. It writes a `manifest.json` for React Native, Flutter, Cordova/Capacitor, NativeScript, and Xamarin extraction; Android APK/Dex and Android bundle paths write child files directly without a manifest.

`hermes decompile` writes the module as one script, `<stem>.js`, in which each closure is nested where the bytecode creates it, and lists every function on its own in `<stem>.functions.js`. For a React Native bundle, the module registrations in the global code (`__d(factory, id, dependencies)`) are read back into a module table in `manifest.json`, and each factory's parameters take Metro's names (`global, require, importDefault, importAll, module, exports, dependencyMap`) unless a global of the same name is read in the bundle. `hermes disasm` emits a per-function summary without a JS surface. Pass `--function <INDEX_OR_NAME>` to select a zero-based index or exact function name, and add `--json` to receive the same instruction list as a structured document. Duplicate names require an index. `hermes info` prints the version, function count, string count, and identifier count.

`flutter dump` reports the four Dart snapshot sections and their sizes. With `--format`, an optional `--engine-symbol-map` accepts the versioned `disrobe.flutter.engine-symbol-map` JSON format. Disrobe applies those names only when the map's GNU build ID matches the ELF input and every address lies inside an image segment. The parser caps the map at 1 MiB and 10,000 unique addresses. `flutter map` parses a Flutter `obfuscation_map.json` into a typed original-to-obfuscated lookup.

```json
{
  "format": "disrobe.flutter.engine-symbol-map",
  "version": 1,
  "identity": {
    "kind": "elf-build-id",
    "value": "b71885094a73117bf90d3cfa05824129"
  },
  "symbols": [
    { "address": 4096, "name": "Dart_Invoke" }
  ]
}
```

`address` is an unsigned virtual address in the input image, not a file offset or image-relative offset. Addresses must be unique. A validated external entry replaces a symbol-table entry at the same address; all other local symbols remain. JSON exports record the map path, format, and matched build ID in `provenance`. The same map can be supplied to a single-file automatic run with `disrobe auto <input> --format json --engine-symbol-map <map>`.

Output shapes below are illustrative.

```text
hermes decompile: OK
  input:        index.android.bundle
  hermes ver:   96
  functions:    8
  with body:    8
  identifiers:  24
  strings:      12
  opcode cov:   100.0% (312 reconstructed / 0 fallback)
  if/loop/try:  3/2/1
  structured:   8 of 8 bodied functions
  source:       ./out/index.android.bundle-hermes/index.android.bundle.js
  functions:    ./out/index.android.bundle-hermes/index.android.bundle.functions.js
  manifest:     ./out/index.android.bundle-hermes/manifest.json
```

```text
flutter kernel: OK
  input:        app.dill
  format ver:   130
  libraries:    3
  classes:      8
  procedures:   21
  fields:       14
  bodies:       21 recovered (byte-exact Dart source from the kernel source table)
  strings:      112
  wrote:        ./out/app-dart-kernel.json
  dart source:  ./out/app-dart-kernel.recovered.dart
```

## Flutter build identity

`disrobe flutter identity` answers which Dart SDK and Flutter release built an app before any deeper analysis, from an APK, an Android App Bundle, an IPA, a zip, or a single `libapp.so`, `libflutter.so`, `App.framework` or `Flutter.framework` binary (ELF32, ELF64, Mach-O and universal Mach-O; PE for `flutter_windows.dll`).

On an APK assembled from the committed fixtures (a real `gen_snapshot` library and an engine stand-in):

```text
APK, 1167009 bytes, sha256 c5e6ff78b8aa522c9023c44d3ac67dc0eb63c421a8fd68490bc9cca8d24f2dd8
snapshot hash     ace654289f5abc240509fc941453ebc5
Dart SDK          3.12.1, 3.12.2
engine Dart       3.12.2
engine revision   83675ed27633283e7fc296c8bca22e841224c096
Flutter           3.44.5, 3.44.6
app    lib/arm64-v8a/libapp.so [arm64-v8a] 2884496 bytes sha256 ed36ebd571c8705ef68c881f6303da4aa337ae11d26458e7ff27ccce98d81859
       build id b718850991b7e341f90d3cfa676a1ece
       _kDartIsolateSnapshotData ace654289f5abc240509fc941453ebc5 product no-code_comments no-dwarf_stack_traces_mode dedup_instructions no-asan no-msan no-tsan no-shared_data arm64 android compressed-pointers
       _kDartVmSnapshotData ace654289f5abc240509fc941453ebc5 product no-code_comments no-dwarf_stack_traces_mode dedup_instructions no-asan no-msan no-tsan no-shared_data arm64 android compressed-pointers
engine lib/arm64-v8a/libflutter.so [arm64-v8a] 2888 bytes sha256 efaf59ac75b6f868ba0462d0bb1addfbb3249c7982a2091117b9381490b3f2a6
       build id a28176b7afc36374ec72f8d11e5f27794dd7410c
       Dart 3.12.2 (stable) built Tue Jun 9 01:11:39 2026 -0700 for android_arm64
```

- The app snapshot hash and feature flags come from the headers behind the exported `_kDartVmSnapshotData` and `_kDartIsolateSnapshotData` symbols (Mach-O's extra leading underscore included); when the symbols are stripped, from a bounded scan for the snapshot magic.
- The engine's Dart version string, its stamped snapshot hash and its 40-digit revisions are read as NUL-terminated strings, so stripped release engines answer too. A GNU build ID (ELF) or `LC_UUID` (Mach-O) and the SHA-256 identify each library, per ABI.
- Two bundled tables turn hashes into releases. `dart_snapshot_hashes.tsv` holds the snapshot hash of every stable Dart SDK tag from 2.0.0, computed the way the Dart build computes it (MD5 over the `runtime/vm` files that `tools/make_version.py` lists at the tag). `flutter_engine_revisions.tsv` holds the engine and Dart revisions every Flutter release tag from 1.0.0 pins. `crates/disrobe-pass-mobile/tests/support/derive_flutter_tables.py` regenerates both from the public repositories.
- Libraries that disagree on the snapshot hash, an app without its engine (or the reverse) for an ABI, and a hash outside the table are reported as findings; nothing is guessed. A hash outside the table usually means a beta, dev or locally patched SDK, or a release newer than the table.

Evidence: `crates/disrobe-pass-mobile/tests/flutter_identity.rs` reads the real `gen_snapshot` outputs in `corpus/mobile/flutter/` and requires the Dart SDK release and revision that `oracle.json` records from the `flutter --version` that built them; a copy with one hash digit changed must claim no release. Authored ELF and Mach-O stand-ins in `corpus/mobile/flutter/identity/` (built by `build.sh`, checked against `llvm-readobj`) cover the other ABIs, IPAs, universal binaries and the disagreement case. Locally, the official Flutter 3.44.6 android-arm64 release engine resolves to its own release.

## Coverage and fidelity

`decompile` reads the header of Hermes bytecode versions v60 through v96, v98, and v99 against the documented layout, and lifts the thirteen versions between v62 and v99 that have a graded opcode table. For v98 and v99 the instruction stream is first mapped onto the classic forms (loose and strict stores, define-own stores, slot stores resolved through the object shape table, the new environment instructions), then lifted by the same code; classes are rebuilt with `$baseClass` and `$derivedClass`, `super(...)` with `Reflect.construct(parent, args, new.target)`, `super.x` with `Reflect.get`, private fields as non-enumerable symbol-keyed properties behind `$privateGet`/`$privateSet`/`$privateHas`, and string switches through `$stringCase`. The compiler lowers v98 generators to a state machine that keeps its frame in environments; the state machine is emitted as is and driven by `$createGenerator`, which implements `next`, `throw` and `return` the way the Hermes generator prototype does. Registers that live across blocks, or that an exception handler reads, become declared variables; a value used once is folded into its use only when no other side effect or variable write would move across it. Calls keep their `this` value, `new` is rebuilt from the create-this/construct/select triple, closures read their captured variables by name across nested functions, and generators and async functions are rebuilt with `yield`. Where a generator's `return()` path runs code of its own (a `finally` block, closing a `for`-`of` iterator, or the delegation loop of `yield*`), the suspension is written as `yield* $yieldResume(value)`, whose iterator turns `return(v)` into a value the recovered code branches on, so the same cleanup runs; `yield*` itself keeps the inner iterator's result objects by identity. Control flow structures to `if`, loops, `switch`, and nested `try`/`catch`, including a `try` left by several exits (a `$exit` selector after the statement picks the continuation). Where those shapes do not fit, as with short-circuit conditions that share a target, the function is laid out as labelled blocks and loops, with `break` and `continue` to labels; this covers every graph the Hermes compiler emits for structured source. `hermes decompile --structuring labeled-blocks` lays out every function that way. When a function's exception handlers do not nest as `try`/`catch` statements, each protected block gets its own `try` whose `catch` jumps to the handler. Only a function whose exception edges make its graph irreducible (seen with `yield*` delegation inside generators) is written as a block dispatcher, which is valid JavaScript with the same behavior. An operation without an exact rendering is written as a call to `$unrecovered("<opcode>")`, which throws when reached, and is counted as declined.

The grader re-executes the output. Fifteen self-authored programs covering control flow, short-circuit conditions, closures, objects, exceptions, generators, generator cleanup on `return()`, `yield*` delegation, async functions, value coercions, construction, function names read against their scope, a Metro module registry, and Metro asset modules are compiled by hermesc 0.12.0 (HBC v89) and run by the Hermes interpreter of the same release. Each decompiled program, run under node, prints exactly what the interpreter printed, with no declined instruction; a recovery with one `+` flipped to `-` fails the same comparison, and the Metro program's module table matches its four `__d` calls. The same programs compiled by the `hermesc` that the react-native npm package ships for React Native 0.69.12 (v85), 0.71.19 (v90), and 0.72.17 (v94) decompile with no declined instruction and print what the interpreter printed (thirteen at v85, whose compiler rejects BigInt literals), and disassemble to exactly what each compiler's `-dump-bytecode` prints: string table, array and object buffers, function names, builtin names, instruction sequences, and exception handlers. One authored sample compiled by the real compiler at each of v62, v71, v74, v76, v83, v84, v85, v89, v90, v94, and v96 decompiles with no declined instruction and prints what its source prints. Laid out entirely as labelled blocks, all 99 of these compiled programs (1,295 functions) still print the same, and removing a labelled `break` changes the output; 18 of their functions remain dispatchers; other versions in the v60-v96 band parse but are not graded against a real compiler. A non-redistributable 66 MiB production bundle parsed the <!-- m:hermes_functions -->122,633<!-- /m -->-function table with no parse failure; all 5,765,066 of its instructions lower to JavaScript with none declined, and 122,625 of its functions structure; the other 8 are generators whose exception edges make the graph irreducible (measured locally, not CI-gated).

Two distinct recovery paths cover two distinct Flutter artifacts.

**Corpus provenance: self-authored sample.** `disrobe_sample/` is self-authored: Flutter
stable SDK, bundled Dart SDK 3.12.2 (windows_x64), kernel format version 130/132,
`gen_snapshot android-arm64-release` in product mode with no DWARF. Its source,
`disrobe_aot_sample.dart`, exercises:

- Classes with final fields, a `const` constructor, a computed getter, and an instance
  method that returns a new instance of its own class
- A top-level recursive function and sequential `if`/return control flow
- Nullable types with `??` and `?.`, string interpolation, a `for`-in loop over a `List`,
  and a non-capturing lambda passed to `.where()`

It does not exercise async or generator functions, a user-defined generic class or
function, a closure that captures an enclosing variable, extension methods, mixins,
`Future`/`Stream` chains, or build_runner-generated code, so recovery of those constructs
is untested.

**Corpus provenance: obfuscated builds.** `pinned_graph_fixture/` is a second
self-authored source built three times by the real `flutter build apk --release`
toolchain (Flutter 3.44.6, Dart 3.12.2): plain, with every class and field renamed, and
with `--obfuscate --split-debug-info=build/symbols`. The obfuscated build is graded, not
merely present: `obfuscated_flutter_build_reports_structure_only` and
`obfuscated_auto_mode_never_claims_source_names` require the declaration graph to report
`StructureOnly` with opaque names and never claim a source name it does not have.

**A real third-party sample, local only.**
`crates/disrobe-pass-mobile/tests/real_flutter_rustdesk.rs` fetches RustDesk 1.4.9's
`arm64-v8a` release APK (AGPL-3.0, 26,871,021 bytes, sha256 pinned in the test and in
`corpus/mobile/flutter/MANIFEST.toml`) and extracts `lib/arm64-v8a/libapp.so` and
`libflutter.so` from the zip in memory; the APK itself is never committed. Reproduce it
with:

```sh
mkdir -p "$TMPDIR/disrobe-scratch/rustdesk-flutter-cache"
curl -sSL -o "$TMPDIR/disrobe-scratch/rustdesk-flutter-cache/rustdesk-1.4.9-aarch64-signed.apk" \
  "https://github.com/rustdesk/rustdesk/releases/download/1.4.9/rustdesk-1.4.9-aarch64-signed.apk"
cargo test -p disrobe-pass-mobile --test real_flutter_rustdesk
```

This result is `[local]`: no CI job populates the cache, so `tests/optional.toml` lists the
sample and a run without it writes a not-measured record instead of passing; without that
entry an absent cache fails the test by name. On this real build the RAW static path recovers
<!-- m:flutter_rustdesk_function_boundaries -->23,471<!-- /m --> function boundaries,
10,351 class-name strings, 28,952 method-name strings, and 1,489 library URIs, each
cross-checked against an independent whole-file `package:*.dart` string scan that finds
1,271 of its own. Every one of those counts is pinned by equality in the test, so a
figure that moves fails the gate rather than drifting silently. RustDesk 1.4.9 was built
by Flutter 3.24 on Dart 3.5, a pinned release, so the declaration-graph path
(`flutter inventory`) walks all 859 isolate clusters and recovers 1,237 libraries, 6,360
classes, 29,620 methods and 1,906 fields, each count equal to the snapshot's declared total
once the unowned VM function and the library-less `Never` class are set aside. Every
`package:` library URL the walk names also appears in the independent string scan, and the
four counts are pinned by equality.

**Dart kernel (`.dill` / `kernel_blob.bin`).** A kernel is the serialized Dart AST. `disrobe` parses the kernel binary format (magic `0x90abcdef`): the footer component index, the string table, per-library class and procedure offset tables, and the embedded `UriSource` table. From the source table it recovers byte-exact original Dart bodies, sliced per procedure by the kernel file offsets. The recovered `.dart` source file is always written beside the JSON without needing `--emit-source`.

**ARM64 AOT snapshot (`libapp.so`).** The AOT snapshot is ordinary AArch64 machine code. `disrobe` locates the four `_kDart*Snapshot*` symbols, recovers class and method names from the isolate-data string table, scans frame prologues to bound functions, and disassembles each body to readable instructions with resolved direct-call and branch targets. `flutter decompile` also recovers the class table estimate, library URIs, and a string pool from the isolate image.

Beyond the disassembly, the release ARM64 path recovers class membership and method-to-class attribution, and lifts each function to nested if/else/while pseudocode through the shared structurer. That lift is gated by a source-free CFG round-trip: when the recovered structure does not round-trip to the same control-flow graph, the function falls back to a flat call list rather than presenting a shape the graph does not support.

Each call in that pseudocode carries its reconstructed argument list. `disrobe` tracks the Dart argument registers, the Dart stack slots that hold arguments past the register file, and the caller's frame slots across the call sequence, then renders each argument as an expression: an immediate, a null or boolean read from the null register, a value produced by an earlier call, a field load by offset, or an object-pool entry. A tail call renders the same way, as a returned call. Pool entries are inlined as literals. On a pinned snapshot version `disrobe` deserializes the object pool per slot, so a call that loads a string, a double, an integer, a list, or a declared name reads that value back at the call site. Inlining is depth-bounded and size-bounded, and a cyclic pool reference stops at the placeholder. An argument the tracker cannot resolve renders as `?`, and an argument produced by a control-flow merge always renders as `?` rather than one branch's value. A call whose arguments cannot be recovered at all keeps the opaque `(...)` form.

**Declaration graph (`flutter inventory` / `flutter inventory-standalone`).** The clustered object graph inside the snapshot data blobs carries the full library, class, method, and field declarations, keyed to the Dart SDK snapshot version and feature tuple that serialized them. `disrobe` reads that graph for every Dart release Flutter stable has shipped since Flutter 3.19: Dart 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10 and 3.11 (all patch releases of a minor share one snapshot hash), and Dart 3.12.1 and 3.12.2, each for Android arm64 in both the plain product tuple and the `--split-debug-info` DWARF tuple. It recovers every class, method with its parameter count, and instance field name.

One table describes the releases, derived from the Dart SDK sources at each tag. Across this range `runtime/vm/class_id.h` dropped the external string classes (Dart 3.4), added `Bytecode` (Dart 3.6) and moved `UnlinkedCall` (Dart 3.9), so each release has its own class-id numbering. Dart 3.3 heads each cluster with a class id and canonical bit where later releases write the object tag word, a loading unit id widened to a full word in Dart 3.5, and a field's kind bits widened to 32 bits in Dart 3.10. The object layouts the walk reads (`runtime/vm/raw_object.h`) and the per-cluster read order (`runtime/vm/app_snapshot.cc`) are otherwise the same across the range.

Each release is graded on a self-authored program in `corpus/mobile/flutter/versions/`, compiled by the official Dart SDK and the `gen_snapshot` of a Flutter release that shipped it, once plain and once the way `--obfuscate --split-debug-info` compiles. Every cluster the walk reads (its kind, object count, and the offset and size of its allocation and fill sections) must equal the cluster report `gen_snapshot --print_cluster_information` wrote while building that snapshot. The declared library, class, function, and field totals must all be accounted for, and the program's classes, methods with their parameter counts, and fields must be recovered. The same bytes relabelled with a neighbouring release's hash fail that grade. The Dart 3.12.2 pin is graded the same way on real `flutter build apk --release` output against the snapshot's own cluster-header totals.

A snapshot compatibility hash outside the pinned set reports `unsupported-version`, naming the Dart releases that hash belongs to, rather than guessing at cluster offsets. Object-pool literals at call sites stay pinned to Dart 3.12.2.

## React Native assets

Metro compiles each `require()` of an image, font, or other file into a module that registers a packager asset record (`__packager_asset`, `httpServerLocation`, `name`, `type`, `hash`, `width`, `height`, `scales`) with the asset registry. `hermes decompile` reads those records back from the bytecode at every version it decompiles and lists them in `manifest.json` under `react_native_assets`, each with the Metro module that registers it and the paths a release build copies it to. On Android that is `res/drawable-<density>/` for image types, one folder per scale, and `res/raw/` for everything else, named by React Native's own rules (location and name lowercased, `/` to `_`, other characters dropped, the leading `assets_` removed). On iOS it is `assets/<location>/<name>@<scale>x.<type>` inside the app, for the scales the iOS build keeps (1, 2, and 3, or the first larger scale, or the last one).

`disrobe mobile recon` does the same for the bundle in `assets/index.android.bundle` of an APK or `Payload/<App>.app/main.jsbundle` of an IPA, whether it is Hermes bytecode or plain JavaScript, and finds each path in the package. In an APK a file is found under the folder as written, under the `-v4` folder `aapt2` links densities into, or, when `aapt2 optimize --shorten-resource-paths` renamed the files, through `resources.arsc`, which still maps the resource name and density to the renamed file; in an IPA it is found under the app directory. A path with none of these is reported missing, as in a base APK whose densities moved to split APKs. In plain JavaScript, a record is read when its object literal starts with the `__packager_asset` key, as Metro writes it, with string, number, boolean, and number-array values.

The record table is graded on an authored Metro bundle compiled at v85, v89, v90, v94, v98, and v99, on the same bundle as plain JavaScript, and on a copy written the way Metro's minifier writes it: each must equal the records the Hermes interpreter printed when it ran the bundle. The paths are graded against React Native's own asset copy step (`saveAssets` with its scale filter and Android and iOS path functions from the React Native CLI) run under node, over the bundle's assets and a set of edge records (Unicode names, numeric densities, `?unstable_path=` locations, `..` segments, raw types, scales outside the iOS set). The package lookup is graded on `aapt2`-linked APKs in `corpus/apk/react-native/` (linked folder names with a Hermes or a JavaScript bundle, and shortened names against the shortening map `aapt2` wrote) and on an IPA laid out as the iOS copy step writes it.

## Detected runtimes

`disrobe mobile detect|extract` routes the packaged JavaScript and .NET runtimes out of an `.apk` or `.ipa`: React Native Hermes, Flutter, Xamarin, Cordova, Capacitor, and NativeScript, each handed to the pass that reads it.

## Android packers and protectors

`disrobe mobile recon app.apk` names the packer or protector an APK carries and, where the payload format and key are public, recovers the original dex files and hands them to the dex pass (`mobile extract` and `auto` route them as children). Each finding lists the anchors it rests on: entry paths inside the APK, the manifest application class, and stub class descriptors inside `classes.dex`.

| Packer | Anchors | Payload |
|---|---|---|
| Qihoo 360 Jiagu | `assets/libjiagu*.so`, `assets/libprotectClass*.so`, `com.stub.StubApp`, `com.qihoo.util.StubApplication` | tail of `classes.dex` located; not recovered (second stage undocumented) |
| Bangcle | `libsecexe.so`, `libsecmain.so`, `assets/bangcle_classes.jar`, `assets/bangcleplugin/` | run-time key |
| SecNeo DexHelper | `libDexHelper.so`, `libSecShell.so`, `assets/classes0.jar` | recovered when the jar's dex entry opens with the published RC4 key and 0xAC tail |
| ijiami | `assets/ijiami.dat`, `libexecmain.so`, `com.shell.SuperApplication` | run-time key |
| Tencent Legu | `libshella-*.so`, `libshell-super.2019.so`, `assets/0OO00l111l1l` | located; NRV and XTEA unpacking is not implemented |
| Baidu, Alibaba mobisec, DexProtector, AppGuard (INCA) | native library names, payload assets, stub classes | run-time key |
| Promon SHIELD | `libshield*.so`, `assets/pbi.bin` | not a dex packer; strings and constants live in native code |
| Pangxie | `libnsecure.so`, `com.merry.wapper.WapperApplication` | recovered (asset dex xored with 0x54) |
| open-source Jiagu (Frezrik) | `com.frezrik.jiagu.StubApp` plus an appended block whose trailer equals the stub size | recovered (AES-128-CBC under the loader's published key, 0x66 header mask) |
| APKProtect, NQ Shield, Naga, LIAPP, AppGuard (NHN) | native library or asset names | payload format undocumented |

A dex counts as recovered only when its header size matches its length and its Adler-32 checksum verifies. The fixtures in `corpus/apk/packers/` are authored mimics: `build.py` writes each APK to match one packer's published layout and builds the packed payloads from dex files compiled for the purpose, which are the reference a recovery must reproduce byte for byte. No packer, protector, or third-party app was run, so a real packed build that differs from the published layout can go unnamed.

## Limits

- Hermes output names registers `r<N>`, parameters `arg<N>`, and captured variables `c<function>_<slot>`; names from debug information are not applied yet. A function keeps its Hermes name; when its body reads a global of the same name, it is written as `({ name: function (...) {...} }).name`, which keeps the name without binding it inside the body. A direct call (`CallDirect`) is declined by name. `yield*` is rebuilt as the loop Hermes compiles it to rather than as one `yield*` expression; it behaves the same, except that the inner result's `done` property is read twice per step. Async functions run through the same promise driver Hermes ships, so their microtask order matches Hermes rather than a native `async` function.
- Bytecode v98 and v99 come from npm `hermes-compiler` 250829098 and 260318099, which React Native 0.84 and later ships. Seventeen authored programs compiled by both compilers disassemble to exactly what each compiler's own `-dump-bytecode` prints: the string table, literal buffers, object shape table, function names, builtin names, instruction sequences, and exception handlers (8,985 instructions at v98 and 8,986 at v99, across 237 functions each). The same programs decompile with no declined instruction and print what their sources print under node; no Hermes v98 interpreter is published, so the reference is the source, not the interpreter. Limits at v98 and v99: generators run as the compiler's state machine rather than as `function*`, and a generator object's prototype is the shared generator prototype rather than the generator function's own `prototype`; private fields are visible to `Object.getOwnPropertySymbols`; block-scoped environments (`-Xes6-block-scoping`, off in the compiler React Native uses) and typed Static Hermes instructions are declined by name.
- Exact Dart source for an optimized AOT function is not byte-recoverable from the machine code (register allocation and inlining are lossy). Use the kernel path for source bodies.
- Instance field names are not recovered by the ARM64 disassembly path (`flutter decompile` / `flutter disasm`); they are only reachable through the declaration graph (`flutter inventory`), and only on a pinned Dart SDK snapshot version.
- The declaration graph path recovers names, not values or optimized-body source; it never guesses a cluster layout for a snapshot compatibility hash it does not have pinned.
