# Mobile (Hermes / Flutter)

`disrobe` detects the runtime inside a mobile package, extracts React Native and other bundles, lifts Hermes bytecode to a JavaScript surface, and recovers Dart source or disassembles the ARM64 AOT snapshot from Flutter artifacts.

## At a glance

| Layer | Coverage |
|---|---|
| Runtimes detected | `react-native-apk`, `react-native-ipa`, `hermes-raw-bytecode`, `flutter-libapp-so`, `flutter-dart-kernel`, `xamarin-apk`, `cordova-apk`, `capacitor-apk`, `nativescript-apk`, `ipa`, `android-apk-dex`, `unknown` |
| Hermes | Bytecode versions v60 through v96, each function lifted to pseudo-JavaScript |
| Dart kernel | `.dill` / `kernel_blob.bin` parsed to byte-exact original Dart bodies from the kernel source table |
| Dart AOT | `libapp.so` AArch64 bodies disassembled with resolved direct-call and branch targets, plus class table, library URIs, and string pool |
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
disrobe flutter decompile libapp.so --out estimate.json
disrobe flutter kernel app.dill --out kernel.json
disrobe flutter disasm libapp.so --emit-listing
disrobe flutter map obfuscation_map.json --out map.json
```

`mobile detect` classifies the package; `mobile extract` pulls bundles out of the container and writes a `manifest.json` listing each artifact.

`hermes decompile` lifts each function back to pseudo-JavaScript. `hermes disasm` emits a per-function summary without a JS surface. `hermes info` prints the version, function count, string count, and identifier count.

`flutter dump` reports the four Dart snapshot sections and their sizes. `flutter map` parses a Flutter `obfuscation_map.json` into a typed original-to-obfuscated lookup.

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

`decompile` handles Hermes bytecode versions v60 through v96 and lifts each function back to pseudo-JavaScript. On a hermesc-built HBC v96 sample (8 functions, CI-gated) every function lifts at 0 fallback opcodes. A non-redistributable 66 MiB production bundle parsed the <!-- m:hermes_functions -->122,633<!-- /m -->-function table with no parse failure (measured locally, not CI-gated).

Two distinct recovery paths cover two distinct Flutter artifacts.

**Dart kernel (`.dill` / `kernel_blob.bin`).** A kernel is the serialized Dart AST. `disrobe` parses the kernel binary format (magic `0x90abcdef`): the footer component index, the string table, per-library class and procedure offset tables, and the embedded `UriSource` table. From the source table it recovers byte-exact original Dart bodies, sliced per procedure by the kernel file offsets. The recovered `.dart` source file is always written beside the JSON without needing `--emit-source`.

**ARM64 AOT snapshot (`libapp.so`).** The AOT snapshot is ordinary AArch64 machine code. `disrobe` locates the four `_kDart*Snapshot*` symbols, recovers class and method names from the isolate-data string table, scans frame prologues to bound functions, and disassembles each body to readable instructions with resolved direct-call and branch targets. `flutter decompile` also recovers the class table estimate, library URIs, and a string pool from the isolate image.

## Limits

- The Hermes path is a structured lifter, not a full decompiler. Variadic call arguments are marked `<arg?>` where the Hermes frame-register layout is not modeled; unreconstructed opcodes appear in disasm form inline.
- Exact Dart source for an optimized AOT function is not byte-recoverable from the machine code (register allocation and inlining are lossy). Use the kernel path for source bodies.
