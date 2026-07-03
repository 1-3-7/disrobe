# Native (PE / ELF / Mach-O)

**disrobe** does **not** compete with Ghidra, IDA, or Binary Ninja on raw decompilation. It is the unpack, symbol-recovery, and chain-detect layer that feeds those tools cleaner input, and it wraps Ghidra headlessly when you want a full decompile in one command.

## Symbol recovery and dumping

```sh
disrobe native symbols app.exe --out symbols.json
```

Dumps symbols, sections, segments, imports, and debug info from a PE / ELF / Mach-O. Demangles and restores Rust and C++ symbols across x86 / ARM / RISC-V / MIPS / PowerPC / SPARC / eBPF / AVR, reading DWARF, PDB, and STABS debug formats. For C++ binaries it recovers the class hierarchy from the in-memory RTTI and vtable layout: ABI, each class's inheritance kind, direct base classes (virtual flagged), virtual-method slot counts, and detected STL templates.

## Disassembly, call graph, and CFG

```sh
disrobe native disasm app.exe --out app.asm                  # recovered per-function listing
disrobe native disasm app.exe --emit cfg-dot --out cfg.dot   # per-function basic-block CFG
disrobe native disasm app.exe --emit json --out disasm.json  # structured instruction stream
disrobe native disasm --raw shellcode.bin --base 0x1000 --bits 64 --syntax intel   # linear sweep
disrobe native callgraph app.exe --out callgraph.dot         # whole-program call graph
```

An in-tree iced-x86 disassembler discovers functions without symbols (call-target and prologue scanning), partitions each into basic blocks, builds the whole-program call graph, and renders the per-function listing or, with `--emit cfg-dot`, the basic-block CFG. `--raw` disassembles a flat code blob with no container, and `--syntax intel|at&t|nasm|masm` selects the dialect for raw output. Each decoded instruction carries its register, memory, and rflags read/write effects, and the native layer can re-encode and relocate instruction blocks (the engine behind `native patch`).

## Patching, signatures, and binary diff

```sh
disrobe native patch app.exe --at 0x1400 --bytes 0x90,0x90 --out patched.exe   # rewrite + revalidate
disrobe native patch app.exe --nop-range 0x1400:0x1410 --out patched.exe        # nop a span
disrobe native sigmaker app.exe --at 0x1400                                      # wildcarded signature
disrobe native diff old.exe new.exe                                             # match functions across builds
```

`native patch` rewrites bytes at a virtual address (or nops a VA span), maps the VA to a file offset, applies the edit, and revalidates the image. `native sigmaker` generates a wildcarded byte signature from the function at an address (immediates and displacements masked via the instruction decoder), then uniqueness-tests it across the image. `native diff` matches functions across two binaries by content, relocation-invariant, and control-flow-graph fingerprints and reports the added, removed, and changed functions. All three work on stripped input through the in-tree function discovery.

## Queryable IR and capabilities

```sh
disrobe query app.exe functions                         # discovered functions, complexity, exports
disrobe query app.exe calls-to malloc                   # call sites to a target
disrobe query app.exe xrefs-to sekret                   # references to a symbol
disrobe query app.exe string-decoders                   # decoder-shaped functions (loops + byte arith)
disrobe query app.exe complexity-over 20                # functions over a cyclomatic threshold
disrobe query app.exe capability network                # instructions tied to a capability
disrobe capabilities app.exe                            # MITRE ATT&CK + MBC behavior report
```

`disrobe query` runs a queryable-IR layer over the disassembled code (`functions`, `calls-to`, `xrefs-to`, `string-decoders`, `complexity-over`, `capability`), symbol-independent and driven by the same function discovery. `disrobe capabilities` runs a rule engine over that IR and reports matched behaviors mapped to MITRE ATT&CK techniques and Malware Behavior Catalog (MBC) IDs, with the matching instruction offsets as per-rule evidence. Both accept a stripped binary directly or a `.dr` envelope.

## Emulation-driven string recovery

```sh
disrobe strings app.exe                                  # static strings + decoder-execution recovery
```

Beyond a static scan, `disrobe strings` locates decoder-shaped functions and drives each through the in-house x86 emulator, recovering the plaintext that only exists after the decoder runs. Emulation-recovered strings are deduplicated against the static set and reported with the decoder and buffer addresses, so a single-byte or multi-byte XOR/sub stack-string scheme yields the decoded text without executing the sample natively.

## Identifying the compiler, packer, and protector

```sh
disrobe native identify app.exe --out identity.json
```

An in-house multi-signal signature engine fingerprints what built and protected a binary through self-consistency-based identification, then routes each finding to the `disrobe` pass that handles it. It detects compilers and toolchains (Go, Rust, MSVC, GCC, Clang, MinGW, Delphi, Nim, Zig, Crystal, Swift, GHC, .NET, Nuitka), packers (UPX, ASPack, PECompact, FSG, MEW, MPRESS, Petite, NSPack, kkrunchy), protectors (Themida, VMProtect, Enigma, Obsidium, Armadillo, ConfuserEx, .NET Reactor, Eazfuscator), installers (NSIS, Inno Setup, InstallShield, AutoIt, PyInstaller, Electron, Bun), linkers (MSVC link via the Rich header, GNU ld, LLD), and code-signing. Every hit carries a `support` route: a Go binary points at `disrobe go recover`, a packed PE at `disrobe native unpack`, a .NET assembly at `disrobe dotnet decompile`, an installer at `disrobe auto`. Virtualizing protectors (Themida, VMProtect) are detect-and-carve only, never a fabricated devirtualization.

## Unpacking native packers

```sh
disrobe native unpack packed.exe --out unpacked.bin
```

Detects the runtime packer and unpacks it. In-house decoders cover UPX (`.text` and `.pdata` byte-identical, ~96% whole loaded image), kkrunchy (byte-exact), NSPack (~99% content-section), MPRESS, Petite, MEW, ASPack, and PECompact. On committed samples ASPack and PECompact rebuild the decompressed section image at its load RVA: the section report confirms the recovered `.text` byte-identical and the import table >=98% byte-identical to the original, both gated in CI, while the packed `.text` of near-random entropy and zero resolvable calls drops to ~6.2-6.5 with hundreds of disassembler-resolvable intra-code calls. Because the whole rebuild is a loaded-memory image rather than a disk-aligned file, the bench marks whole-output byte-identity n/a. MEW rebuilds a flat image of the committed Sysinternals samples, read as the entropy drop to ~4.2-4.9 and tens of thousands of decoded instructions. FSG decodes through the same aPLib-clone path but ships no committed fixture (its samples live under the gitignored `.developer/` tree), so no number reproduces from a checkout. ASProtect, Morphine, nPack, NeoLite, and Yoda's Crypter are recovered by driving their unpack stub through the in-house x86 stub emulator: the decompressor or stream decryptor runs to the original entry point inside the emulator, then the reconstructed sections are read back and sliced byte-for-byte (Yoda's Crypter `.rsrc` recovers byte-identical and `.text` decrypts to full plaintext). Yoda's Protector is detect + resource-carve, its stream key being a runtime-only value absent from the file. On UPX and NSPack the whole-image residual is the loader-rebuilt zone (bound import address table and base relocations): those addresses are resolved by the OS loader at run time and are not present in the packed stream, not a decoder gap. The virtualizing protector tier (VMProtect, Themida, Enigma, and 15+ others) is detect-and-carve: the stub is still driven through the emulator, but the original code is decrypted only by a per-machine key assembled after the stub validates an un-instrumented host (RDTSC deltas, debugger-handler identity, BOUND/FPU exception fingerprints). That key is not present in the file, so faithful recovery is an information-theoretic wall; **disrobe** carves what survives in place and reports the wall rather than fabricating an unpack. Per-fixture recovery scores are pinned in `corpus/native/packers/MANIFEST.toml`.

## Devirtualizing a bytecode VM

```sh
disrobe native devirt protected.exe --out recovered/
```

`disrobe native devirt` targets the bytecode-VM tier rather than the compression tier. It locates the interpreter, fingerprints each handler's micro-op behaviorally by probing it through the in-tree x86 emulator (so a per-build handler permutation does not break the lift), recovers the handler-to-opcode table, reconstructs the VM CFG, and lifts the handler bytecode to a re-executable IR plus pseudo-code. The output directory receives the recovered listing, the pseudo-code, and a `devirt.manifest.json` (schema `disrobe.native.devirt/v1`).

The lifter is validated end-to-end on a self-authored Tigress-shape bytecode VM: the recovered IR re-executes to the same outputs as the original across arithmetic, loop, and branch programs, lifted from machine code alone (`vm_devirt_oracle.rs`). The commercial front-ends (VMProtect, Themida, Code Virtualizer, Enigma, WinLicense, PELock) mutate their handler set per build; the lifter is the generic engine and the Tigress-shape VM is its validated level, but `disrobe` ships no per-family devirtualizer for the commercial protectors, so those are detected and section-carved rather than lifted back to source. A handler stream assembled at run time from a per-machine key, or fetched over the network, is an information-theoretic residual; protector identification and section carve stay available for every family.

## Forensic primitives

```sh
disrobe native entropy app.exe                           # ASCII heat-strip + byte histogram + packed-region runs
disrobe native entropy app.exe --format svg --svg map.svg # dark-theme SVG entropy map with section overlays
disrobe native entropy app.exe --format json --out e.json # the disrobe.native.entropy/v0 document
disrobe native signatures app.exe --out sigs.json        # AES T-tables, SHA/MD5 IV+K, ChaCha20 sigma
disrobe native signatures app.exe --flirt db.sig         # match against an IDA FLIRT database
disrobe native fingerprint app.exe                       # crypto + FLIRT + string-xref sidecar
disrobe native graph app.exe --out imports.dot           # import/export table as Graphviz DOT
disrobe native sbom app.exe --out app.cyclonedx.json     # CycloneDX 1.5 SBOM from cargo-auditable metadata
```

## Entropy map & byte histogram

`disrobe native entropy` slides a 4 KB window across the file computing Shannon entropy (bits/byte) to locate packed, compressed, or encrypted regions, and renders the profile three ways via `--format text|json|svg`:

- **text** (default): a Unicode heat-strip sparkline (one glyph per 4 KB block, taller = higher entropy), a 16-bucket ASCII byte-frequency bar chart, and a list of contiguous **high-entropy runs** (entropy >= 7.0 bits/byte) with their file offsets, the candidate packed/encrypted regions. Pass `--out <path>` to also drop the JSON document.
- **svg**: a self-contained, dependency-free neutral-gray **entropy map**. Each block is a column colored on a calm-gray to amber to red ramp, with PE/ELF/Mach-O section boundaries (parsed from the file's own section table) overlaid as labeled dashed markers and a color legend. Written to `./out/<stem>.entropy.svg` or the explicit `--svg <path>` (which implies SVG rendering). The SVG is byte-stable for a given input (no clock or RNG) and all section names are XML-escaped.
- **json**: the machine-readable `disrobe.native.entropy/v0` document: per-block entropy, the sparkline/heat-strip strings, the 16-bucket histogram, the detected high-entropy runs, and the section spans.

The reusable rendering logic lives in `disrobe_pass_native::entropy_viz` (`entropy_sparkline`, `byte_histogram`, `histogram_ascii_16`, `high_entropy_runs`, `render_entropy_svg`) so other tools can embed it.

## Full decompile via Ghidra

```sh
disrobe native decompile app.exe --out decompiled/
```

Runs Ghidra headlessly (install it with `disrobe install-deps ghidra`) and returns pseudo-C alongside the standardized emits. This is the one place where an external native engine is the legitimate primary: **disrobe**'s job is to hand it a clean, unpacked, symbol-rich input.
