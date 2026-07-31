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

## Counted twice

Every report carries `inventory.declared` and `inventory.residue` beside `inventory.counts`, because a count the walk produces on its own cannot show that the walk reached everything.

`inventory.declared` is what the snapshot declares. Each clustered section opens with a total object count and a run of cluster headers, and each header states how many objects of one class id follow. The parser refuses a snapshot whose headers do not add up to the declared total, so those per class totals cannot shrink without the file contradicting itself. `inventory.declared` sums the Library, Class, PatchClass, Function, and Field headers across the VM and isolate snapshots.

`inventory.counts` is what the inventory walk attached to an owning class and library, and `inventory.residue` is what it could not attach, counted where each object is dropped rather than inferred by subtraction. Attached plus dropped has to equal what the headers declared. Run the tool on any snapshot and the two sides are in the JSON: a walk that stops early reports fewer attached declarations without the declared totals moving, which is the gap made visible instead of hidden.

## Real Flutter fixtures

The test fixtures were built with Flutter stable 3.44.6 using `flutter build apk --release`. The renamed build changes `ReceiptValidator` to `VoucherValidator` and is rebuilt from source. The obfuscated build uses `--obfuscate --split-debug-info`. `oracle.json` records toolchain revisions, compatibility hash, artifact hashes, per snapshot declared object totals, global inventory counts, the attribution residue, and known declarations. Its `counts_provenance` block states how each pinned count was arrived at.

`tests/inventory_derivation.rs` holds the pinned figures to the snapshot rather than to a past run: the cluster headers must declare the pinned per snapshot totals, and attached plus dropped must equal them for classes, methods, and fields. On these three builds the residue is one function, the single Function the VM snapshot declares, which has no owner because that snapshot declares zero Class and zero PatchClass objects and isolate classes are allocated above the VM object range. The library count runs one above the declared Library total because the `Never` class carries a null library reference and the walk opens one entry no Library object backs.

Flutter and Dart ship no report of class, method, and field counts for a built snapshot, so there is no toolchain figure to compare against. `dart compile aot-snapshot --write-v8-snapshot-profile-to` would count objects independently but changes the emitted snapshot and would break the pinned artifact hashes.

Run `tests/fixtures/flutter_3_44_6/rebuild.ps1` with the recorded Flutter revision to recreate an Android project from the committed manifest, build all three variants, extract each `lib/arm64-v8a/libapp.so`, verify every artifact hash, and re-derive every count and declared total through the recovery binary. The provenance test also confirms that the two source files differ only by the validator class rename.

The source build recovers 2 of 2 known named classes, 3 of 3 known methods, and 2 of 2 known fields in `package:disrobe_dart_fixture/main.dart`. The rename test requires the old class name to disappear and the new name to appear. The obfuscated test requires non-empty structure and an explicit opaque-name report.

## Current boundary

This crate does not reconstruct identifiers removed by obfuscation; a matching Flutter symbol map can restore them. Native body devirtualization is not implemented in this module version. NIR and pseudo-Dart body lifting are out of scope for this round and define the next increment.
