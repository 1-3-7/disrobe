# Native (PE / ELF / Mach-O)

`disrobe` ships its own in-tree x86-64 and AArch64 decompiler, and around it the layer that recovers a binary's symbols, disassembles it, identifies what built and protected it, and patches, fingerprints, or diffs it. Ghidra and IDA still lead on large, deeply nested native binaries, so `disrobe` also hands them clean, unpacked, symbol-rich input and can drive Ghidra headlessly in one command.

Two adjacent surfaces have their own pages: [native decompile](./native-decompile.md) for the in-tree decompiler and the Ghidra backend, and [native unpacking](./native-unpack.md) for packers, protectors, and bytecode-VM devirtualization.

## At a glance

| Surface | Support |
|---|---|
| Containers | PE, ELF, Mach-O, plus a flat code blob with `--raw` |
| Architectures | x86 / ARM / RISC-V / MIPS / PowerPC / SPARC / eBPF / AVR |
| Debug formats | DWARF, PDB, STABS |
| Demangling | Rust and C++ symbols, with the C++ class hierarchy recovered from RTTI and vtable layout |
| Function discovery | Call-target and prologue scanning on stripped input, basic-block partition, whole-program call graph |
| Identification | Compilers, packers, protectors, installers, linkers, and code-signing, each finding routed to the pass that handles it |
| Authenticode | Digest recomputation and PKCS#7 chain walk to a single verdict from nine outcomes |
| Queryable IR | `functions`, `calls-to`, `xrefs-to`, `string-decoders`, `complexity-over`, `capability` |
| Capabilities | MITRE ATT&CK technique and MBC ID mapping, with matching instruction offsets as per-rule evidence |
| String recovery | Static scan plus decoder execution through the in-house x86 emulator |
| Editing | Byte patch and nop-range at a virtual address, wildcarded signature generation, cross-build function diff |
| Object models | Delphi and C++Builder classes with parents, published properties, fields, methods, dynamic method handlers and interfaces, enumeration members, string literals, DFM form resources, and compiler release identification |
| Forensics | Entropy map (text / JSON / SVG), crypto and FLIRT signatures, import/export graph, CycloneDX SBOM |

## Commands

```sh
disrobe native symbols app.exe --out symbols.json            # symbols, sections, imports, debug info, RTTI

disrobe native disasm app.exe --out app.asm                   # recovered per-function listing
disrobe native disasm app.exe --emit cfg-dot --out cfg.dot    # per-function basic-block CFG
disrobe native disasm app.exe --emit json --out disasm.json   # structured instruction stream
disrobe native disasm --raw shellcode.bin --base 0x1000 --bits 64 --syntax intel   # linear sweep
disrobe native callgraph app.exe --out callgraph.dot          # whole-program call graph

disrobe native patch app.exe --at 0x1400 --bytes 0x90,0x90 --out patched.exe   # rewrite + revalidate
disrobe native patch app.exe --nop-range 0x1400:0x1410 --out patched.exe        # nop a span
disrobe native sigmaker app.exe --at 0x1400                                     # wildcarded signature
disrobe native diff old.exe new.exe                                             # match functions across builds

disrobe native identify app.exe --out identity.json           # compiler, packer, protector, signature verdict

disrobe query app.exe functions                         # discovered functions, complexity, exports
disrobe query app.exe calls-to malloc                   # call sites to a target
disrobe query app.exe xrefs-to sekret                   # references to a symbol
disrobe query app.exe string-decoders                   # decoder-shaped functions (loops + byte arith)
disrobe query app.exe complexity-over 20                # functions over a cyclomatic threshold
disrobe query app.exe capability network                # instructions tied to a capability
disrobe capabilities app.exe                            # MITRE ATT&CK + MBC behavior report

disrobe strings app.exe                                 # static strings + decoder-execution recovery

disrobe native entropy app.exe                           # ASCII heat-strip + byte histogram + packed-region runs
disrobe native entropy app.exe --format svg --svg map.svg # dark-theme SVG entropy map with section overlays
disrobe native entropy app.exe --format json --out e.json # the disrobe.native.entropy/v0 document
disrobe native signatures app.exe --out sigs.json        # AES T-tables, SHA/MD5 IV+K, ChaCha20 sigma
disrobe native signatures app.exe --flirt db.sig         # match against an IDA FLIRT database
disrobe native fingerprint app.exe                       # crypto + FLIRT + string-xref sidecar
disrobe native graph app.exe --out imports.dot           # import/export table as Graphviz DOT
disrobe native sbom app.exe --out app.cyclonedx.json     # CycloneDX 1.5 SBOM from cargo-auditable metadata
```

## Coverage and fidelity

### Symbol recovery and dumping

`native symbols` dumps symbols, sections, segments, imports, and debug info from a PE / ELF / Mach-O. It demangles and restores Rust and C++ symbols across x86 / ARM / RISC-V / MIPS / PowerPC / SPARC / eBPF / AVR, reading DWARF, PDB, and STABS debug formats. For C++ binaries it recovers the class hierarchy from the in-memory RTTI and vtable layout: ABI, each class's inheritance kind, direct base classes (virtual flagged), virtual-method slot counts, and detected STL templates.

### Disassembly, call graph, and CFG

An in-tree iced-x86 disassembler discovers functions without symbols (call-target and prologue scanning), partitions each into basic blocks, builds the whole-program call graph, and renders the per-function listing or, with `--emit cfg-dot`, the basic-block CFG. `--raw` disassembles a flat code blob with no container, and `--syntax intel|at&t|nasm|masm` selects the dialect for raw output. Each decoded instruction carries its register, memory, and rflags read/write effects, and the native layer can re-encode and relocate instruction blocks (the engine behind `native patch`).

### Patching, signatures, and binary diff

`native patch` rewrites bytes at a virtual address (or nops a VA span), maps the VA to a file offset, applies the edit, and revalidates the image. `native sigmaker` generates a wildcarded byte signature from the function at an address (immediates and displacements masked via the instruction decoder), then uniqueness-tests it across the image. `native diff` matches functions across two binaries by content, relocation-invariant, and control-flow-graph fingerprints and reports the added, removed, and changed functions. All three work on stripped input through the in-tree function discovery.

### Queryable IR and capabilities

`disrobe query` runs a queryable-IR layer over the disassembled code (`functions`, `calls-to`, `xrefs-to`, `string-decoders`, `complexity-over`, `capability`), symbol-independent and driven by the same function discovery. `disrobe capabilities` runs a rule engine over that IR and reports matched behaviors mapped to MITRE ATT&CK techniques and Malware Behavior Catalog (MBC) IDs, with the matching instruction offsets as per-rule evidence. Both accept a stripped binary directly or a `.dr` envelope.

### Emulation-driven string recovery

Beyond a static scan, `disrobe strings` locates decoder-shaped functions and drives each through the in-house x86 emulator, recovering the plaintext that only exists after the decoder runs. Emulation-recovered strings are deduplicated against the static set and reported with the decoder and buffer addresses, so a single-byte or multi-byte XOR/sub stack-string scheme yields the decoded text without executing the sample natively.

### Identifying the compiler, packer, and protector

An in-house multi-signal signature engine fingerprints what built and protected a binary through self-consistency-based identification, then routes each finding to the `disrobe` pass that handles it. It detects compilers and toolchains (Go, Rust, MSVC, GCC, Clang, MinGW, Delphi, Nim, Zig, Crystal, Swift, GHC, .NET, Nuitka), packers (UPX, ASPack, PECompact, FSG, MEW, MPRESS, Petite, NSPack, kkrunchy), protectors (Themida, VMProtect, Enigma, Obsidium, Armadillo, ConfuserEx, .NET Reactor, Eazfuscator), installers (NSIS, Inno Setup, InstallShield, AutoIt, PyInstaller, Electron, Bun), linkers (MSVC link via the Rich header, GNU ld, LLD), and code-signing. Every hit carries a `support` route: a Go binary points at `disrobe go recover`, a packed PE at `disrobe native unpack`, a .NET assembly at `disrobe dotnet decompile`, an installer at `disrobe auto`.

### Unpacking and byte-level recovery

`disrobe native unpack` is graded per section against a committed original rather than by whether the output merely parses. Three families ship one packed-and-original pair each, so their figures reproduce from a clean checkout:

| Family | `.text` | `.rdata` | `.data` | `.rsrc` | Content total |
|---|---|---|---|---|---|
| FSG (`Hash.exe`) | 18188 / 18188 | 2311 / 3988 | 33212 / 33212 | 1552 / 4672 | 55263 / 60060 |
| NSPack (`hash.exe`) | 18188 / 18188 | 3988 / 3988 | 33212 / 33212 | 2333 / 4672 | 57721 / 60060 |
| Petite (`hello.exe`) | 70796 / 70796 | 15734 / 18396 | 456 / 456 | none | 86986 / 89648 |

`.text` and `.data` are byte-identical for all three, and NSPack's `.rdata` is byte-identical as well, so the decompressors themselves are exact and the residual is placement and fixups rather than lost payload. The content denominator is the original's own section span and is asserted by equality, so a recovery that emits fewer bytes scores worse instead of shrinking what it is measured against. The byte-identical sections are held as a membership list rather than a count, so a section that stops recovering exactly drops out of the list instead of being masked by another section improving. Two spans are reported and they are not interchangeable: the per-section total above counts `.rsrc`, while an older whole-image gate measures NSPack over `.text`, `.rdata` and `.data` only and reads 99.36% for the same fixture. Relocations are classified as loader-rebuilt and scored separately, because the OS resolves them at load time.

The residuals have specific causes worth knowing when reading a recovered image. FSG's `.rdata` gap is the import descriptor region: the stub's block-destination table names one aPLib stream per original section, all four are decoded, and the descriptor block is decoded then deliberately withheld from the recovered image because the stub writes it over original `.rdata` content at run time. NSPack's `.rdata` reaches byte identity instead, because its import lookup and address tables are rebuilt from the module record the stub carries rather than left for the loader to resolve. The `.rsrc` gap is shared across families, at 1552 / 4672 for FSG and 2333 / 4672 for NSPack, and it narrowed once the original resource-directory tree is placed at its own RVA rather than wherever the decompressed image left it; what remains is the part each stub reconstructs at run time. Larger uncommitted vendor samples score lower on the whole-image measure for the same two reasons, and no figure is published for them because those samples are not committed and nothing pins them. kkrunchy and kkrunchy classic recover their payload byte-exactly against committed fixtures.

An absent committed fixture is never a silent pass. Setting `DISROBE_REQUIRE_PACKER_FIXTURES=1`, which CI does, turns a missing committed fixture into a failure, a skip always prints the fixture path and states that nothing was graded, and a fixture that is present but unreadable is a hard failure in every mode, because that is how a quarantined or truncated sample would otherwise stop grading unnoticed (`committed_packer_byte_recovery.rs`, `fsg_unpack.rs`, `nspack_byte_recovery.rs`, `petite_unpack.rs`, `kkrunchy_unpack.rs`).

### Authenticode verification

For a signed PE, `identify` verifies the Authenticode signature rather than only noting its presence. It recomputes the SHA-1/256/384/512 digest over the Authenticode hash range (the file minus the checksum field, the certificate-table directory entry, and the certificate table itself) and compares it to the digest the signature claims. It walks the PKCS#7/CMS signer chain (RSA PKCS#1 v1.5 and ECDSA P-256/P-384) up to an embedded bundle of eight trusted code-signing roots, and requires the code-signing extended key usage on the leaf certificate. It verifies any RFC 3161 timestamp, both its own signer chain and its message imprint, before trusting that timestamp to extend validity. The outcome is a single verdict, one of Valid, NoSignature, HashMismatch, Expired, SelfSigned, UntrustedChain, WrongKeyUsage, UnsupportedAlgorithm, or MalformedSignature, written into `identity.json` with the computed and claimed hashes, the certificate chain, and the timestamp. The verdicts are graded against real signed PE fixtures carrying injected defects: a flipped `.text` byte, a forged timestamp, a wrong-EKU leaf, and self-signed and expired chains, each asserted to its expected verdict. The computed digest is cross-checked against `osslsigncode` where it is installed, and live Microsoft-signed `System32` binaries reach Valid against the embedded roots (`authenticode_oracle.rs`).

### Delphi and C++Builder RTTI

For a Delphi or C++Builder binary, the native Delphi analyzer (`disrobe_pass_native::delphi::analyze`) recovers the published object model from the compiled RTTI. It locates virtual method table anchors across the three ABI eras (pre-2009 32-bit, Delphi 2009+ 32-bit, and 64-bit), accepting a class only when its table is self-consistent, and recovers each class's name, parent, instance size, published properties with the ancestor that introduced each, published methods, published fields with their declared class, dynamic method and message handlers, and implemented interface identifiers. Enumeration member names, ordinal ranges and set element types come from the referenced type records. Compiled-in string literals are recovered from the reference-count header across the pre-2009, code page and 64-bit layouts, accepted only when the declared length lands exactly on the terminator. The unit initialization table is reached by following the entry point stub, giving the unit count and each unit's initialization and finalization address, and is refused unless every address lands in an executable section. Each class is tagged as runtime library or author code from its RTTI unit name, so an analyst can read only the author's classes. The compiler release is named only when independent signals agree: the table layout era, a linked runtime package name, dotted unit scope names, and build toolchain path strings. When they disagree the report says so rather than choosing one. It also decodes the binary DFM form resources (`TPF0`) back to their textual `object ... end` representation.

Form decoding is compared byte for byte against form streams and renderings both produced by the Free Pascal RTL converters, over five committed cases covering collections, nested collections, child objects, binary data blocks, value lists, sets, control characters and 64-bit integers; the converter source and a regeneration script ship beside the fixtures. Float rendering is excluded and remains ungraded, because the reference renderer's float format differs from Delphi's. The virtual method table and published table walks are graded against the documented layout rather than against a Delphi-compiled binary, so they catch a regression but not an error shared between the reader and the specification transcription. Each table is rejected whole unless every entry validates, so a wrong layout yields nothing rather than invented names. False-positive controls confirm no class, field, dynamic method, interface, type record or string literal is produced from real `kernel32.dll`, `ntdll.dll`, `user32.dll` or `shell32.dll`.

### Nim, Zig, Crystal, and D binaries

These four compilers erase the source, so recovery works from each binary's own tables rather than from anything resembling the original file. `disrobe` detects the toolchain, demangles its name scheme, and recovers the symbol and metadata surface the compiler left behind. Where DWARF survives, aggregate members come back with full types, including multi-dimensional array dimensions and const/volatile qualifiers, so a field reads as `const u8[4]` or `u8[2][3]` rather than an opaque blob. A stripped D PE, which carries neither DWARF nor a name table, is a wall: the format is identified and nothing further is claimed.

### Entropy map and byte histogram

`disrobe native entropy` slides a 4 KB window across the file computing Shannon entropy (bits/byte) to locate packed, compressed, or encrypted regions, and renders the profile three ways via `--format text|json|svg`:

- `text` (default): a Unicode heat-strip sparkline (one glyph per 4 KB block, taller = higher entropy), a 16-bucket ASCII byte-frequency bar chart, and a list of contiguous high-entropy runs (entropy >= 7.0 bits/byte) with their file offsets, the candidate packed or encrypted regions. Pass `--out <path>` to also drop the JSON document.
- `svg`: a self-contained neutral-gray entropy map with no external dependency. Each block is a column colored on a calm-gray to amber to red ramp, with PE/ELF/Mach-O section boundaries (parsed from the file's own section table) overlaid as labeled dashed markers and a color legend. Written to `./out/<stem>.entropy.svg` or the explicit `--svg <path>` (which implies SVG rendering). The SVG is byte-stable for a given input (no clock or RNG) and all section names are XML-escaped.
- `json`: the machine-readable `disrobe.native.entropy/v0` document: per-block entropy, the sparkline/heat-strip strings, the 16-bucket histogram, the detected high-entropy runs, and the section spans.

The reusable rendering logic lives in `disrobe_pass_native::entropy_viz` (`entropy_sparkline`, `byte_histogram`, `histogram_ascii_16`, `high_entropy_runs`, `render_entropy_svg`) so other tools can embed it.

## Limits

- Ghidra and IDA still lead on large, deeply nested native binaries. `disrobe`'s job there is to hand them a clean, unpacked, symbol-rich input; see [native decompile](./native-decompile.md) for the in-tree decompiler and the Ghidra backend.
- Virtualizing protectors (Themida, VMProtect) are detect-and-carve only, never a fabricated devirtualization. See [native unpacking](./native-unpack.md) for what survives and why.
- Authenticode chain validation walks to an embedded bundle of eight trusted code-signing roots and covers RSA PKCS#1 v1.5 and ECDSA P-256/P-384. Anything outside that lands as `UnsupportedAlgorithm` or `UntrustedChain` rather than a pass.
- The Delphi VMT walk accepts a class only when its VMT is self-consistent, so a partially-overwritten or hand-built table yields no class rather than a guessed one.
