# Mobile (Hermes / Flutter)

**disrobe** detects the runtime inside a mobile package, extracts React Native and other bundles, lifts Hermes bytecode to a JavaScript surface, and recovers Dart source or disassembles the ARM64 AOT snapshot from Flutter artifacts.

## Runtime detection and extraction

```sh
disrobe mobile detect app.apk
disrobe mobile extract app.apk --out bundles/
disrobe mobile hermes index.android.bundle --out disasm/
disrobe mobile flutter libapp.so --out layout.json
```

`detect` classifies a package as one of: `react-native-apk`, `react-native-ipa`, `hermes-raw-bytecode`, `flutter-libapp-so`, `flutter-dart-kernel`, `xamarin-apk`, `cordova-apk`, `capacitor-apk`, `nativescript-apk`, `ipa`, `android-apk-dex`, or `unknown`. `extract` pulls bundles out of the container and writes a `manifest.json` listing each artifact.

## Hermes

```sh
disrobe hermes decompile index.android.bundle --out surface/
disrobe hermes disasm index.android.bundle --out disasm/
disrobe hermes info index.android.bundle
```

`decompile` handles Hermes bytecode versions v60 through v96 and lifts each function back to pseudo-JavaScript. On a hermesc-built HBC v96 sample (8 functions, CI-gated) every function lifts at 0 fallback opcodes. A non-redistributable 66 MiB production bundle parsed the 122,633-function table with no parse failure (measured locally, not CI-gated). `disasm` emits a per-function summary without a JS surface. `info` prints the version, function count, string count, and identifier count.

This is a structured lifter, not a full decompiler. Variadic call arguments are marked `<arg?>` where the Hermes frame-register layout is not modeled; unreconstructed opcodes appear in disasm form inline.

Output shape (illustrative):

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

## Flutter

```sh
disrobe flutter dump libapp.so --out layout.json
disrobe flutter decompile libapp.so --out estimate.json
disrobe flutter kernel app.dill --out kernel.json
disrobe flutter disasm libapp.so --emit-listing
disrobe flutter map obfuscation_map.json --out map.json
```

Two distinct recovery paths cover two distinct Flutter artifacts.

**Dart kernel (`.dill` / `kernel_blob.bin`).** A kernel is the serialized Dart AST. **disrobe** parses the kernel binary format (magic `0x90abcdef`): the footer component index, the string table, per-library class and procedure offset tables, and the embedded `UriSource` table. From the source table it recovers byte-exact original Dart bodies, sliced per procedure by the kernel file offsets. The recovered `.dart` source file is always written beside the JSON without needing `--emit-source`.

Output shape (illustrative):

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

**ARM64 AOT snapshot (`libapp.so`).** The AOT snapshot is ordinary AArch64 machine code. **disrobe** locates the four `_kDart*Snapshot*` symbols, recovers class and method names from the isolate-data string table, scans frame prologues to bound functions, and disassembles each body to readable instructions with resolved direct-call and branch targets. `flutter decompile` also recovers the class table estimate, library URIs, and a string pool from the isolate image.

`flutter dump` reports the four Dart snapshot sections and their sizes. `flutter map` parses a Flutter `obfuscation_map.json` into a typed original-to-obfuscated lookup.

Exact Dart source for an optimized AOT function is not byte-recoverable from the machine code (register allocation and inlining are lossy); use the kernel path for source bodies.
