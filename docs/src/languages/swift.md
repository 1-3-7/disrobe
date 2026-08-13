# Swift / Objective-C

`disrobe` extracts the type metadata the Objective-C and Swift runtimes leave in a native binary, demangles it, parses SwiftShield rename mappings into a lookup for downstream use, and rebuilds the dylibs a dyld shared cache bundles into standalone Mach-O images.

## At a glance

| Layer | Coverage |
|---|---|
| Objective-C metadata | `__objc_classlist`, `__objc_catlist`, `__objc_protolist`: classes, categories, protocols, ivars, properties, method selectors with type encodings |
| Swift metadata | `__swift5_types`, `__swift5_fieldmd`, `__swift5_proto`: type names, stored fields, conformances, symbols demangled |
| Containers | Single slice via `disrobe swift classdump`; raw thin and fat Mach-O binaries via `disrobe macho classdump`, which walks every slice |
| dyld shared cache | Header layouts `legacy`, `local-symbols`, `slide-mappings`, `sub-caches`, `relocated-images`; bundled dylibs rebuilt as standalone Mach-O images, per-image `__LINKEDIT`, slide info versions 1 to 5, sibling sub-cache and `.symbols` files |
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
disrobe macho dyldcache dyld_shared_cache_arm64e --out ./out/cache-dylibs
```

`classdump` reconstructs the type interface from the two metadata sources the runtime leaves in the binary. Beside the JSON, it writes a `.swift` declaration file with recovered type signatures when reflection metadata yields declarations; source-level function bodies do not survive in this metadata.

`shield-undo` parses a SwiftShield mapping. SwiftShield renames symbols to high-entropy identifiers and emits an `obf ==> original` mapping in the `.dSYM`. `disrobe` writes that mapping as a lookup for downstream use; class-dump does not apply it automatically. `xor-decrypt` decodes printable strings from a single-byte XOR blob when the caller supplies `--key`. Its tests cover hand-authored model fixtures, not SwiftConfidential output.

`macho dump` reports the header, load commands, segments, sections, and any `LC_ENCRYPTION_INFO` or `LC_ENCRYPTION_INFO_64` records. `macho fat` walks a fat binary and reports each slice's CPU type, subtype, and offset.

`macho dyldcache` rebuilds every dylib the cache bundles and writes each one under `--out` at a path taken from its install name. It reads the single file you name and writes compact images. Use `disrobe auto` on a cache that is split across sibling files or when you want images with a rebuilt `__LINKEDIT`.

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

The demangler recovers async functions, actor and distributed-actor entities, and opaque return types. It also recovers key-path and protocol-witness thunks, partial-apply forwarders, Objective-C bridging thunks, attached macro expansions, and cross-module protocol conformance descriptors and witness tables. Each arm is checked against a real `swift-demangle` run (`arm_coverage.rs`).

Objective-C calls compile to `objc_msgSend`, so a raw disassembly shows only indirect calls into the runtime. When the chain pipeline recovers native function bodies from a Mach-O (`disrobe chain` / `disrobe auto` over a Mach-O), each `objc_msgSend`, `objc_msgSendSuper`, `objc_alloc`, and `objc_alloc_init` call site is resolved back to its concrete selector, the receiver class where it is statically determinable, and a rendered Objective-C message expression such as `[NSString stringWithUTF8String:x2]`. The dispatch maps are built from the binary's `__objc_selrefs` and `__objc_classrefs`, the dyld bind opcodes, and the `__stubs` section, then a bounded per-call backward walk over an arm64 or x86-64 def-use model traces the selector and receiver into the call.

The resolution is graded on real clang-compiled fixtures for both arm64 and x86-64 stripped dylibs: every message send in the fixture recovers with the correct selector and receiver class and zero false positives, and the rendered expressions match the source (`objc_dispatch_sends.rs`).

### dyld shared cache

A dyld shared cache packs many system dylibs into one file. `disrobe` claims a file that carries the `dyld_v1` magic and whose header parses. A file that only starts with the magic is left to another pass.

The offset of the mapping table fixes which header layout the cache uses. `disrobe` names that layout `legacy`, `local-symbols`, `slide-mappings`, `sub-caches`, or `relocated-images`. It reads the image list from the legacy header fields when they are set, and from the relocated image fields otherwise. The cache report carries the layout beside the architecture, header size, UUID, platform, format version, the simulator and chained-fixups flags, the mapping, image, and sub-cache counts, the sub-cache entry kind, whether local symbols sit in a separate symbols file, one entry per slide region naming its version or the version number `disrobe` does not support, the mappings whose file range runs past the end of the file, the pairs of mappings whose address ranges overlap, and up to 4096 install names.

Each image is rebuilt from the mappings that cover its segment addresses, and its segment and section file offsets are rewritten to point at the recovered bytes. Compact output packs the segments back to back. Page-aligned output starts every segment on a `0x4000` boundary and replaces `__LINKEDIT` with one built for that image alone. A rebuilt `__LINKEDIT` holds a symbol table, an indirect symbol table, and a string table for that image, and it copies the image's dyld info blobs, chained-fixups blob, exports trie, function starts, and data-in-code table out of the cache file that holds them. The `LC_CODE_SIGNATURE` offset and size are set to zero, so a recovered image is unsigned. Dysymtab tables the image does not carry are zeroed instead of left pointing into the cache. Two runs over the same cache produce the same bytes.

The cache keeps each image's local symbol names in a run of its own. The `legacy`, `local-symbols`, and `slide-mappings` layouts use the narrow entry, which keys each run by the image's file offset in the primary file. The `sub-caches` and `relocated-images` layouts use the wide entry, which keys each run by the image's offset from the cache base, and they move the runs into a separate symbols file when the header carries a symbol-file UUID. `disrobe` reads both forms and appends the run for an image to the symbol table it builds for that image.

Slide info records the pointers the cache builder rewrote to cache addresses. `disrobe` reads versions 1, 2, 3, 4, and 5, and writes each pointer back to the value the image declares. An authenticated pointer is recorded with its key (`IA`, `IB`, `DA`, or `DB`), its diversity value, and its address-diversity bit, and the pointer in the recovered image holds the bare target. Each image records up to 65536 authenticated pointers and reports the full count beside a flag that states whether the list was cut. A slide-info version outside 1 to 5 stops the image, and the error names the version it found.

The cache container in the tests is written to the header layouts above, and the image inside it is a compiled Swift dylib committed to the corpus. Recovery is graded against that original file's segment bytes, symbol table, exported symbols, and function starts (`dyld_cache_reconstruction.rs`, `dyld_cache_chain.rs`). Slide info is graded end to end through a rebuilt image for versions 3 and 5, and at the page walk that decodes them for versions 1, 2, and 4.

### Sibling cache files

A cache can declare sibling files that hold the rest of its mappings. `disrobe` locates them by computing names from the primary file you named. For sub-cache N it looks for `<primary>.N`, and for a single-digit index it also looks for the zero-padded `<primary>.0N`. For the unmapped local symbols it looks for `<primary>.symbols`. A file suffix declared inside the cache is never used as a path. Such a suffix is rejected before any file is opened when it holds `..`, a path separator, `:`, one of `*`, `?`, `"`, `<`, `>`, `|`, or a byte outside graphic ASCII.

A missing `.symbols` file does not stop recovery. Each image keeps exactly the symbol table it declares, and the run continues.

A missing numbered sibling does stop recovery, because the segments it holds are unreachable. The chain refuses, and the error names the sibling it looked for, how many images it could not reach, and the segment that was out of reach for each one.

### Recovered dylibs in the chain

`disrobe auto` and `disrobe chain` detect the cache, write the cache report as JSON, and emit each recovered dylib as a child artifact that continues through the chain. Both commands pass the input path down, which is how the sibling files are found. Children are page-aligned images with a rebuilt `__LINKEDIT`. A child keeps its install name as its relative path, with the leading separator and any `.` or `..` component dropped. Every character outside graphic ASCII becomes `_`, and so does each of `:`, `*`, `?`, `"`, `<`, `>`, and `|`. An install name that leaves nothing after that becomes `dyld-cache-image`.

```sh
disrobe auto dyld_shared_cache_arm64e --out ./out/cache-chain
```

The chain refuses a split cache when it has no path to compute sibling names from. It refuses in the same way when the path it is given is not a readable file.

## Limits

- Swift and Objective-C compile to native machine code. Source-level function bodies are not part of the runtime metadata; native code can still be analyzed by the native pass. This pass recovers the metadata the runtimes need at run time.
- A dispatch site whose selector or class cannot be traced within the backward-walk window is left unannotated rather than guessed, so a spurious annotation counts as a soundness failure.
- `disrobe macho dyldcache` reads the one file you name and writes compact images. It does not rebuild `__LINKEDIT`, so a compact image keeps the symbol table offsets the cache gave it. It does not read sibling cache files. It stops at the first image it cannot reach instead of reporting a partial result.
- The chain handles a cache of at most 256 images. A cache above that count is refused whole, and the error points at `disrobe macho dyldcache`, which carries the limits above.
- One rebuilt image is capped at 512 MiB, one whole-cache run at 1 GiB, and one cache family at 12 GiB across its files. A cache that needs more than a cap is refused rather than truncated.
- A recovered image is unsigned. `disrobe` clears the `LC_CODE_SIGNATURE` offset and size whenever it rebuilds `__LINKEDIT`.
- FairPlay-encrypted regions (App Store DRM) are reported detect-only via `LC_ENCRYPTION_INFO`: the decryption key is not present in the binary, so class-dump of those regions is an information-theoretic wall.
