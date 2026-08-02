# Swift / Objective-C

`disrobe` extracts the type metadata the Objective-C and Swift runtimes leave in a native binary, demangles it, and parses SwiftShield rename mappings into a lookup for downstream use.

## At a glance

| Layer | Coverage |
|---|---|
| Objective-C metadata | `__objc_classlist`, `__objc_catlist`, `__objc_protolist`: classes, categories, protocols, ivars, properties, method selectors with type encodings |
| Swift metadata | `__swift5_types`, `__swift5_fieldmd`, `__swift5_proto`: type names, stored fields, conformances, symbols demangled |
| Containers | Single slice via `disrobe swift classdump`; raw thin and fat Mach-O binaries via `disrobe macho classdump`, which walks every slice |
| Rename obfuscators | SwiftShield mapping parser |
| String blobs | Explicit-key single-byte XOR blob decoding for model fixtures |
| Message dispatch | `objc_msgSend`, `objc_msgSendSuper`, `objc_alloc`, and `objc_alloc_init` sites resolved to selector, receiver class, and a rendered message expression |
| Mach-O surface | Header, load commands, segments, sections, fat slices, `LC_ENCRYPTION_INFO` records |

## Commands

```sh
disrobe swift classdump App.app/App --out dump.json
disrobe swift shield-undo map.txt --out renames.json
disrobe swift xor-decrypt blob.bin --key 0x55 --out strings.json

disrobe macho classdump universal.bin --out dump
disrobe macho dump App.app/App
disrobe macho fat universal.bin
```

`classdump` reconstructs the type interface from the two metadata sources the runtime leaves in the binary, writing a header-style interface listing. Beside the JSON it writes a `.swift` declaration file with recovered type signatures; source-level function bodies do not survive in this metadata.

`shield-undo` parses a SwiftShield mapping. SwiftShield renames symbols to high-entropy identifiers and emits an `obf ==> original` mapping in the `.dSYM`. `disrobe` writes that mapping as a lookup for downstream use; class-dump does not apply it automatically. `xor-decrypt` decodes printable strings from a single-byte XOR blob when the caller supplies `--key`. Its tests cover hand-authored model fixtures, not SwiftConfidential output.

`macho dump` reports the header, load commands, segments, sections, and any `LC_ENCRYPTION_INFO` or `LC_ENCRYPTION_INFO_64` records. `macho fat` walks a fat binary and reports each slice's CPU type, subtype, and offset.

Output shape (illustrative):

```text
swift classdump: OK
  input:        App
  cpu/bits:     arm64 / Bits64
  swift types:  24
  reflected:    18
  mangled syms: 312
  demangled:    312
  swift declarations: ./out/App-swift.swift
  wrote:        ./out/App-swift.json
```

## Coverage and fidelity

The Objective-C side walks `__objc_classlist`, `__objc_catlist`, and `__objc_protolist` to recover classes, categories, protocols, ivars, properties, and method selectors with their type encodings. The Swift side parses the reflection sections (`__swift5_types`, `__swift5_fieldmd`, `__swift5_proto`) and demangles the symbols to recover type names, stored fields, and conformances.

Objective-C calls compile to `objc_msgSend`, so a raw disassembly shows only indirect calls into the runtime. When the chain pipeline recovers native function bodies from a Mach-O (`disrobe chain` / `disrobe auto` over a Mach-O), each `objc_msgSend`, `objc_msgSendSuper`, `objc_alloc`, and `objc_alloc_init` call site is resolved back to its concrete selector, the receiver class where it is statically determinable, and a rendered Objective-C message expression such as `[NSString stringWithUTF8String:x2]`. The dispatch maps are built from the binary's `__objc_selrefs` and `__objc_classrefs`, the dyld bind opcodes, and the `__stubs` section, then a bounded per-call backward walk over an arm64 or x86-64 def-use model traces the selector and receiver into the call.

The resolution is graded on real clang-compiled fixtures for both arm64 and x86-64 stripped dylibs: every message send in the fixture recovers with the correct selector and receiver class and zero false positives, and the rendered expressions match the source (`objc_dispatch_sends.rs`).

## Limits

- Swift and Objective-C compile to native machine code. Source-level function bodies are not part of the runtime metadata; native code can still be analyzed by the native pass. This pass recovers the metadata the runtimes need at run time.
- A dispatch site whose selector or class cannot be traced within the backward-walk window is left unannotated rather than guessed, so a spurious annotation counts as a soundness failure.
- FairPlay-encrypted regions (App Store DRM) are reported detect-only via `LC_ENCRYPTION_INFO`: the decryption key is not present in the binary, so class-dump of those regions is an information-theoretic wall.
