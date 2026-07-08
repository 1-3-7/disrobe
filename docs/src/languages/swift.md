# Swift / Objective-C

Swift and Objective-C compile to native machine code; function bodies are gone at compile time. What survives in the binary is the type metadata the Objective-C and Swift runtimes need at run time. **disrobe** extracts that metadata, demangles it, and reverses the two dominant rename obfuscators so a dump of a shielded binary reads with its original names.

## Commands

```sh
disrobe swift classdump App.app/App --out dump.json
disrobe swift shield-undo map.txt --out renames.json
disrobe swift confidential-decrypt blob.bin --key 0x55 --out strings.json

disrobe macho classdump App.ipa --out dump.json
disrobe macho dump App.app/App
disrobe macho slices universal.bin
```

## Class-dump

`classdump` reconstructs the type interface from two metadata sources the runtime leaves in the binary.

The Objective-C side walks `__objc_classlist`, `__objc_catlist`, and `__objc_protolist` to recover classes, categories, protocols, ivars, properties, and method selectors with their type encodings.

The Swift side parses the reflection sections (`__swift5_types`, `__swift5_fieldmd`, `__swift5_proto`) and demangles the symbols to recover type names, stored fields, and conformances.

The output is a header-style interface listing. Beside the JSON it writes a `.swift` source file with all recovered type declarations. `disrobe swift classdump` handles single-slice inputs; for fat binaries and `.ipa` containers use `disrobe macho classdump`, which walks every slice.

Output shape (illustrative):

```text
swift classdump: OK
  input:        App
  cpu/bits:     arm64 / Bits64
  swift types:  24
  reflected:    18
  mangled syms: 312
  demangled:    312
  swift source: ./out/App-swift.swift
  wrote:        ./out/App-swift.json
```

## Rename-undo

`shield-undo` reverses a SwiftShield run. SwiftShield renames symbols to high-entropy identifiers and emits an `obf ==> original` mapping in the `.dSYM`. **disrobe** parses that mapping and builds the undo lookup, so a subsequent class-dump of the shielded binary reads with the original names.

`confidential-decrypt` recovers plaintext strings from a SwiftConfidential XOR-obfuscated blob given its single-byte key (`--key`, default `0x55`).

## Objective-C message dispatch

Objective-C calls compile to `objc_msgSend`, so a raw disassembly shows only indirect calls into the runtime. When the chain pipeline recovers native function bodies from a Mach-O (`disrobe chain` / `disrobe auto` over a Mach-O), each `objc_msgSend`, `objc_msgSendSuper`, `objc_alloc`, and `objc_alloc_init` call site is resolved back to its concrete selector, the receiver class where it is statically determinable, and a rendered Objective-C message expression such as `[NSString stringWithUTF8String:x2]`. The dispatch maps are built from the binary's `__objc_selrefs` and `__objc_classrefs`, the dyld bind opcodes, and the `__stubs` section, then a bounded per-call backward walk over an arm64 or x86-64 def-use model traces the selector and receiver into the call. A site whose selector or class cannot be traced within the window is left unannotated rather than guessed, so a spurious annotation counts as a soundness failure.

The resolution is graded on real clang-compiled fixtures for both arm64 and x86-64 stripped dylibs: every message send in the fixture recovers with the correct selector and receiver class and zero false positives, and the rendered expressions match the source (`objc_dispatch_sends.rs`).

## Mach-O commands

`disrobe macho dump` reports the header, load commands, segments, sections, and any `LC_ENCRYPTION_INFO` or `LC_ENCRYPTION_INFO_64` records. `disrobe macho slices` walks a fat binary and reports each slice's CPU type, subtype, and offset.

FairPlay-encrypted regions (App Store DRM) are reported detect-only via `LC_ENCRYPTION_INFO`: the decryption key is not present in the binary, so class-dump of those regions is an information-theoretic wall.
