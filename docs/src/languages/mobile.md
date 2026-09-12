# Mobile (Hermes / Flutter)

`disrobe` detects the runtime inside a mobile package, extracts React Native and other bundles, lifts Hermes bytecode to a JavaScript surface, and recovers Dart source or disassembles the ARM64 AOT snapshot from Flutter artifacts.

## At a glance

| Layer | Coverage |
|---|---|
| Runtimes detected | `react-native-apk`, `react-native-ipa`, `hermes-raw-bytecode`, `flutter-libapp-so`, `flutter-dart-kernel`, `xamarin-apk`, `cordova-apk`, `capacitor-apk`, `nativescript-apk`, `ipa`, `android-apk-dex`, `unknown` |
| Hermes | Bytecode versions v60 through v96 parse against the documented header layout; v76, v84, and v96 lift to pseudo-JavaScript against a real hermesc-built sample |
| Dart kernel | `.dill` / `kernel_blob.bin` parsed to byte-exact original Dart bodies from the kernel source table |
| Dart AOT | `libapp.so` AArch64 bodies disassembled with resolved direct-call and branch targets, plus class table, library URIs, and string pool |
| Dart AOT declaration graph | full library/class/method/field inventory, with method parameter counts, from a `libapp.so` or four standalone snapshot blobs on a pinned Dart SDK snapshot version |
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
```

`mobile detect` classifies the package; `mobile extract` pulls bundles out of the container. It writes a `manifest.json` for React Native, Flutter, Cordova/Capacitor, NativeScript, and Xamarin extraction; Android APK/Dex and Android bundle paths write child files directly without a manifest.

`hermes decompile` lifts each function back to pseudo-JavaScript. `hermes disasm` emits a per-function summary without a JS surface. Pass `--function <INDEX_OR_NAME>` to select a zero-based index or exact function name, and add `--json` to receive the same instruction list as a structured document. Duplicate names require an index. `hermes info` prints the version, function count, string count, and identifier count.

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
  source:       ./out/index.android.bundle-hermes/index.android.bundle.js
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

## Coverage and fidelity

`decompile` reads the header of Hermes bytecode versions v60 through v96 against the documented layout. Lifting each function back to pseudo-JavaScript is graded against a real hermesc-built sample at v76, v84, and v96 only; other versions in the v60-v96 band parse but are not graded against a real compiler. On a hermesc-built HBC v96 sample (8 functions, CI-gated) every function lifts at 0 fallback opcodes. A non-redistributable 66 MiB production bundle parsed the <!-- m:hermes_functions -->122,633<!-- /m -->-function table with no parse failure (measured locally, not CI-gated).

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

This result is `[local]`: no CI job populates the cache, so it never runs there, and
`DISROBE_REQUIRE_RUSTDESK_FLUTTER=1` fails the run instead of skipping it when the cache
is absent. On this real build the RAW static path recovers
<!-- m:flutter_rustdesk_function_boundaries -->23,471<!-- /m --> function boundaries,
10,351 class-name strings, 28,952 method-name strings, and 1,489 library URIs, each
cross-checked against an independent whole-file `package:*.dart` string scan that finds
1,271 of its own. Every one of those counts is pinned by equality in the test, so a
figure that moves fails the gate rather than drifting silently. RustDesk's Dart snapshot
falls outside the pinned Dart 3.12.2 android-arm64 product tuple, so the
declaration-graph path (`flutter inventory`) reports `unsupported-version` on it rather
than guessing at a cluster layout it has no pin for.

**Dart kernel (`.dill` / `kernel_blob.bin`).** A kernel is the serialized Dart AST. `disrobe` parses the kernel binary format (magic `0x90abcdef`): the footer component index, the string table, per-library class and procedure offset tables, and the embedded `UriSource` table. From the source table it recovers byte-exact original Dart bodies, sliced per procedure by the kernel file offsets. The recovered `.dart` source file is always written beside the JSON without needing `--emit-source`.

**ARM64 AOT snapshot (`libapp.so`).** The AOT snapshot is ordinary AArch64 machine code. `disrobe` locates the four `_kDart*Snapshot*` symbols, recovers class and method names from the isolate-data string table, scans frame prologues to bound functions, and disassembles each body to readable instructions with resolved direct-call and branch targets. `flutter decompile` also recovers the class table estimate, library URIs, and a string pool from the isolate image.

Beyond the disassembly, the release ARM64 path recovers class membership and method-to-class attribution, and lifts each function to nested if/else/while pseudocode through the shared structurer. That lift is gated by a source-free CFG round-trip: when the recovered structure does not round-trip to the same control-flow graph, the function falls back to a flat call list rather than presenting a shape the graph does not support.

Each call in that pseudocode carries its reconstructed argument list. `disrobe` tracks the Dart argument registers, the Dart stack slots that hold arguments past the register file, and the caller's frame slots across the call sequence, then renders each argument as an expression: an immediate, a null or boolean read from the null register, a value produced by an earlier call, a field load by offset, or an object-pool entry. A tail call renders the same way, as a returned call. Pool entries are inlined as literals. On a pinned snapshot version `disrobe` deserializes the object pool per slot, so a call that loads a string, a double, an integer, a list, or a declared name reads that value back at the call site. Inlining is depth-bounded and size-bounded, and a cyclic pool reference stops at the placeholder. An argument the tracker cannot resolve renders as `?`, and an argument produced by a control-flow merge always renders as `?` rather than one branch's value. A call whose arguments cannot be recovered at all keeps the opaque `(...)` form.

**Declaration graph (`flutter inventory` / `flutter inventory-standalone`).** The clustered object graph inside the snapshot data blobs carries the full library, class, method, and field declarations, keyed to the exact Dart SDK snapshot version and feature tuple that serialized them. `disrobe` reads that graph directly for the pinned Dart 3.12.2 Android arm64 build (both the plain product tuple and the `--split-debug-info` DWARF tuple): every class, method with its parameter count, and instance field name, cross-checked on real `flutter build apk --release` output against the snapshot's own cluster-header totals. A snapshot compatibility hash outside the pinned set reports `unsupported-version` rather than guessing at cluster offsets.

## Detected runtimes

`disrobe mobile detect|extract` routes the packaged JavaScript and .NET runtimes out of an `.apk` or `.ipa`: React Native Hermes, Flutter, Xamarin, Cordova, Capacitor, and NativeScript, each handed to the pass that reads it.

## Limits

- The Hermes path is a structured lifter, not a full decompiler. Variadic call arguments are marked `<arg?>` where the Hermes frame-register layout is not modeled; unreconstructed opcodes appear in disasm form inline.
- Exact Dart source for an optimized AOT function is not byte-recoverable from the machine code (register allocation and inlining are lossy). Use the kernel path for source bodies.
- Instance field names are not recovered by the ARM64 disassembly path (`flutter decompile` / `flutter disasm`); they are only reachable through the declaration graph (`flutter inventory`), and only on a pinned Dart SDK snapshot version.
- The declaration graph path recovers names, not values or optimized-body source; it never guesses a cluster layout for a snapshot compatibility hash it does not have pinned.
