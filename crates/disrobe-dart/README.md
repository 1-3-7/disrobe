# disrobe-dart

`disrobe-dart` recovers declaration metadata from Flutter and Dart full AOT snapshots. It locates the four snapshot symbols in an ELF `libapp.so`, validates the snapshot header, performs allocation and fill passes over the clustered object graph, resolves references, and emits a library, class, method, and field inventory as JSON.

The current parser supports Flutter 3.44.6 with Dart 3.12.2 for Android arm64 product snapshots. Both product feature tuples produced by ordinary release and split-debug-info release builds are represented in the layout descriptor table. Declaration reference counts and field indexes are part of each descriptor. A compatibility hash without an exact feature tuple returns `unsupported-features`. An unknown compatibility hash returns `unsupported-version` before any cluster layout is read. The JSON field `snapshot_compatibility_hash` is not the SDK Git revision.

## Command line

```text
disrobe-dart elf path/to/libapp.so
disrobe-dart standalone vm_snapshot_data vm_snapshot_instructions isolate_snapshot_data isolate_snapshot_instructions
disrobe-dart --names opaque elf path/to/obfuscated/libapp.so
```

`--names opaque` is the correct choice when build provenance says `--obfuscate` was used. The snapshot header does not prove that source identifiers were obfuscated. Auto mode never labels identifiers as source names. It reports structure-only only when application declarations exhibit a dominant short-token pattern, otherwise name provenance is unclassified.

## Real Flutter fixtures

The test fixtures were built with Flutter stable 3.44.6 using `flutter build apk --release`. The renamed build changes `ReceiptValidator` to `VoucherValidator` and is rebuilt from source. The obfuscated build uses `--obfuscate --split-debug-info`. `oracle.json` records toolchain revisions, compatibility hash, artifact hashes, global inventory counts, and known declarations.

Run `tests/fixtures/flutter_3_44_6/rebuild.ps1` with the recorded Flutter revision to recreate an Android project from the committed manifest, build all three variants, extract each `lib/arm64-v8a/libapp.so`, and verify every artifact hash. The provenance test also confirms that the two source files differ only by the validator class rename.

The source build recovers 2 of 2 known named classes, 3 of 3 known methods, and 2 of 2 known fields in `package:disrobe_dart_fixture/main.dart`. The rename test requires the old class name to disappear and the new name to appear. The obfuscated test requires non-empty structure and an explicit opaque-name report.

## Current boundary

This crate does not reconstruct identifiers removed by obfuscation; a matching Flutter symbol map can restore them. Native body devirtualization is not implemented in this module version. NIR and pseudo-Dart body lifting are out of scope for this round and define the next increment.
