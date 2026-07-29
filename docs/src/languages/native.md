# Native (PE / ELF / Mach-O)

`disrobe` does **not** compete with Ghidra, IDA, or Binary Ninja on raw decompilation. It is the unpack, symbol-recovery, and chain-detect layer that feeds those tools cleaner input, and it wraps Ghidra headlessly when you want a full decompile in one command.

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

For a signed PE, `identify` verifies the Authenticode signature rather than only noting its presence. It recomputes the SHA-1/256/384/512 digest over the Authenticode hash range (the file minus the checksum field, the certificate-table directory entry, and the certificate table itself) and compares it to the digest the signature claims. It walks the PKCS#7/CMS signer chain (RSA PKCS#1 v1.5 and ECDSA P-256/P-384) up to an embedded bundle of eight trusted code-signing roots, and requires the code-signing extended key usage on the leaf certificate. It verifies any RFC 3161 timestamp, both its own signer chain and its message imprint, before trusting that timestamp to extend validity. The outcome is a single verdict, one of Valid, NoSignature, HashMismatch, Expired, SelfSigned, UntrustedChain, WrongKeyUsage, UnsupportedAlgorithm, or MalformedSignature, written into `identity.json` with the computed and claimed hashes, the certificate chain, and the timestamp. The verdicts are graded against real signed PE fixtures carrying injected defects: a flipped `.text` byte, a forged timestamp, a wrong-EKU leaf, and self-signed and expired chains, each asserted to its expected verdict. The computed digest is cross-checked against `osslsigncode` where it is installed, and live Microsoft-signed `System32` binaries reach Valid against the embedded roots (`authenticode_oracle.rs`).

## Delphi and C++Builder RTTI

For a Delphi or C++Builder binary, the native Delphi analyzer (`disrobe_pass_native::analyze_delphi`) recovers the published object model from the compiled RTTI. It locates virtual-method-table anchors across the three ABI eras (pre-2009 32-bit, Delphi 2009+ 32-bit, and 64-bit), accepting a class only when its VMT is self-consistent (the self-pointer slot points back at the table), and recovers each class's name, parent, instance size, published properties with the ancestor that introduced each, and published methods. It also decodes the binary DFM form resources (`TPF0`) back to their textual `object ... end` representation.

DFM decoding is graded byte-for-byte against reference form text (root class, object count, and field values), the VMT walk recovers a two-class inheritance chain with per-property attribution on a constructed image, and a false-positive control confirms no class is produced from real `kernel32.dll`, `ntdll.dll`, or `user32.dll`.

## Unpacking native packers

```sh
disrobe native unpack packed.exe --out unpacked.bin
```

Detects the runtime packer and unpacks it. In-house decoders cover UPX (`.text` and `.pdata` byte-identical, ~96% whole loaded image), MPRESS, Petite, MEW, ASPack, and PECompact, plus NSPack whose vendor fixtures are not committed (local-only, no number reproduces from a clean checkout); kkrunchy and kkrunchy classic ship committed fixtures and recover their payload at a pinned 100.00% floor from a clean checkout. On committed samples ASPack and PECompact rebuild the decompressed section image at its load RVA: the section report confirms the recovered `.text` byte-identical and the import table >=98% byte-identical to the original, both gated in CI, while the packed `.text` of near-random entropy and zero resolvable calls drops to ~6.2-6.5 with hundreds of disassembler-resolvable intra-code calls. Because the whole rebuild is a loaded-memory image rather than a disk-aligned file, the bench marks whole-output byte-identity n/a. MEW rebuilds a flat image of the committed Sysinternals samples, read as the entropy drop to ~4.2-4.9 and tens of thousands of decoded instructions. FSG, NSPack, and Petite decode through their in-house decoders but ship no committed fixture (their samples live under the gitignored `.developer/` tree), so no number reproduces from a checkout. ASProtect, Morphine, nPack, NeoLite, and Yoda's Crypter are recovered by driving their unpack stub through the in-house x86 stub emulator: the decompressor or stream decryptor runs to the original entry point inside the emulator, then the reconstructed sections are read back and sliced byte-for-byte (Yoda's Crypter `.rsrc` recovers byte-identical and `.text` decrypts to full plaintext). Yoda's Protector is detect + resource-carve, its stream key being a runtime-only value absent from the file. On UPX and NSPack the whole-image residual is the loader-rebuilt zone (bound import address table and base relocations): those addresses are resolved by the OS loader at run time and are not present in the packed stream, not a decoder gap. The virtualizing protector tier (VMProtect, Themida, Enigma, and 15+ others) is detect-and-carve: the stub is still driven through the emulator, but the original code is decrypted only by a per-machine key assembled after the stub validates an un-instrumented host (RDTSC deltas, debugger-handler identity, BOUND/FPU exception fingerprints). That key is not present in the file, so faithful recovery is an information-theoretic wall; `disrobe` carves what survives in place and reports the wall rather than fabricating an unpack. Per-fixture recovery scores are pinned in `corpus/native/packers/MANIFEST.toml`.

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

## Entropy map and byte histogram

`disrobe native entropy` slides a 4 KB window across the file computing Shannon entropy (bits/byte) to locate packed, compressed, or encrypted regions, and renders the profile three ways via `--format text|json|svg`:

- `text` (default): a Unicode heat-strip sparkline (one glyph per 4 KB block, taller = higher entropy), a 16-bucket ASCII byte-frequency bar chart, and a list of contiguous high-entropy runs (entropy >= 7.0 bits/byte) with their file offsets, the candidate packed or encrypted regions. Pass `--out <path>` to also drop the JSON document.
- `svg`: a self-contained neutral-gray entropy map with no external dependency. Each block is a column colored on a calm-gray to amber to red ramp, with PE/ELF/Mach-O section boundaries (parsed from the file's own section table) overlaid as labeled dashed markers and a color legend. Written to `./out/<stem>.entropy.svg` or the explicit `--svg <path>` (which implies SVG rendering). The SVG is byte-stable for a given input (no clock or RNG) and all section names are XML-escaped.
- `json`: the machine-readable `disrobe.native.entropy/v0` document: per-block entropy, the sparkline/heat-strip strings, the 16-bucket histogram, the detected high-entropy runs, and the section spans.

The reusable rendering logic lives in `disrobe_pass_native::entropy_viz` (`entropy_sparkline`, `byte_histogram`, `histogram_ascii_16`, `high_entropy_runs`, `render_entropy_svg`) so other tools can embed it.

## Native decompile (in-tree x86-64 / AArch64 -> C or Rust)

```sh
disrobe native decompile app.exe --out decompiled/                 # x86-64 -> C, default backend
disrobe native decompile app.exe --format rust --out decompiled/   # x86-64 -> idiomatic Rust
disrobe native decompile app_arm64 --out decompiled/               # aarch64 -> pseudo-C, symbolic devirt on by default
disrobe native decompile app_arm64 --no-devirt --out decompiled/   # aarch64 without the symbolic devirtualizer
```

`--backend native` (the default) is disrobe's own x86-64 and AArch64 decompiler: no external tool, no install step. It performs whole-program call resolution over every function the module discovers, not isolated per-function guessing. Each function is leaf-recovered in the object's context, its outgoing calls are walked to resolve each callee's real name and integer arity against the sibling function set (falling back to the object's own relocations when a call target is a link-time placeholder in an unlinked object), then the caller is re-recovered with that call graph stitched in. Dense switch dispatch is recovered from the binary's own jump table rather than guessed. A function with no outgoing calls degrades to a plain leaf recovery, so stitching only ever improves recovery, never regresses it. AArch64 function bodies lift to full pseudo-code through the same shared IR, not disassembly alone. AArch64 function discovery is symbol-table-based today (the linear-sweep function finder is x86-only), so a stripped AArch64 binary surfaces fewer functions than its unstripped sibling, which enumerates and decompiles in full.

Types are inferred from the access shape rather than left as raw registers. A pointer walked at several fixed offsets recovers as a struct with named fields (`p->field_8`), a base indexed by a scaled register recovers as an array (`a[i]`), and offsets read at conflicting widths recover as a union. The calling convention is inferred per function, including x86 `thiscall` (implicit `this` in `ecx`) and `vectorcall` (SSE/AVX register arguments), so the recovered signature matches how the function is actually called.

Alongside the source, `native decompile` writes a `types.json` sidecar (schema `disrobe.native.types/v1`) recording the recovered integer width and signedness of each frame slot. The `disrobe-typerec` crate reads those signals straight from instruction semantics, subregister access, `movsx`/`movzx`, `div`/`idiv`, `sar`/`shr`, and signed against unsigned compares, and resolves them over a lattice with union-find. A frame slot the compiler reused for two variables is split back into distinct objects by a region-typed memory-SSA and live-range pass, so a reused slot recovers as two types instead of one blurred type that loses the signedness of both, and the same crate grades the struct, array, and union shapes the decompiler recovers from those access paths. When a recovered call reaches a known library or OS function, resolved through the PE import table or ELF relocations to a curated libc, kernel32, and ws2_32 prototype database, that function's parameter and return types are propagated backward into the caller's locals through the same region memory-SSA and written into `types.json` as `api_slots`, each carrying its `library!function` provenance so an API-derived type is distinguishable from an inferred one; an unresolved import, an ordinal-only import, or a call whose backpropagated type conflicts abstains rather than guessing, and those API-derived caller-local types are graded on a stripped-versus-unstripped clang corpus against the unstripped DWARF, recovering pointer, integer-width, and sign with zero wrong types. Where the byte stream carries no sign signal for a slot, the sidecar reports it as unknown rather than guessing. Graded against an unstripped sibling's DWARF on an `-O0` corpus, integer width and struct field offset and per-field width recover at recall 1.0, live-range splitting lifts signedness recall from 0.25 to 1.0 on the slot-reuse cases, and mutation checks confirm the grader rejects seeded-wrong widths, signs, field offsets, and merged or invented fields instead of passing everything.

On the AArch64 path a symbolic devirtualizer runs before structuring, on by default in a full build and disabled with `--no-devirt`. It folds conditional arms it can prove dead against the path constraints, then hands the simplified function to the structurer. The fold is transactional: on any proof miss or budget exhaustion it reverts to the original function, so it can only ever replace a construct with a proven-equivalent one and never invents an edge. Per-function fold counts and status land in the decompile `manifest.json` under `devirt`; control-flow-flattening deflatten and jump-table edge rewrite are noted as deferred on this path.

Auto-vectorized loops are recovered to their scalar meaning: the C backend recognizes SSE/AVX reduction and pointer-walk map kernels that gcc and clang emit at `-O2`/`-O3` and lowers them back to the equivalent scalar loop, tracing each argument to its pristine ABI register so a compiler's entry-sequence register swap does not misattribute the length to the output pointer. Reassociation-unsafe floating-point vector loops are rejected rather than lowered to a wrong scalar form.

Every recovered function is graded by execution-differential recompilation against real gcc, clang, or rustc, never against disrobe's own prior output. The AArch64 lift is held to the same bar against real `clang -O2` machine code, and the struct, array, and union recovery is asserted on recompiled-and-executed fixtures rather than by inspection. The vectorized-loop recovery is held to the same bar: the recovered scalar loop is recompiled and its output compared bit-for-bit against the original compiled kernel across a spread of input lengths, and on Linux at least one gcc `-O3` pointer-walk reduction must recover and execute-prove (`simd_devirt_oracle.rs`). Output lands at `<out>/<stem>.c` or `<out>/<stem>.rs` alongside a `manifest.json` (schema `disrobe.native.decompile/v1`) listing which functions recovered, which did not and why, and the emitted symbol name for each, plus the `types.json` sidecar described above.

## Full decompile via Ghidra

```sh
disrobe native decompile app.exe --backend ghidra --out decompiled/
```

Runs Ghidra headlessly (install it with `disrobe install-deps ghidra`) and returns pseudo-C alongside the standardized emits. Reach for this on large, deeply nested binaries where Ghidra's whole-program type and structure recovery still leads: `disrobe`'s job there is to hand it a clean, unpacked, symbol-rich input.
