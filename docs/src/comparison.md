# Comparison

How `disrobe` sits next to the established tool for each ecosystem. The aim is not to win every cell. For several targets a mature dedicated tool already exists and is the better choice for that one format; `disrobe`'s value is doing all of them from one binary, behind a deterministic pipeline that records what it recovered and what it could not.

Recovery is always measured against an independent reference, never the tool's own output, and lossy results are reported as measured. The honest limits are listed at the bottom of this page and in [Limits](./introduction.md).

## Source recovery (bytecode to source)

| Ecosystem | Established tools | Where `disrobe` differs |
|---|---|---|
| **Python** | pycdc, pylingual, uncompyle6, decompyle3 | One engine spans 3.6-3.15; each construct is recompiled and diffed opcode-for-opcode. uncompyle6 stops near 3.8 and decompyle3 near 3.9; the ML decompilers are non-deterministic and carry benchmark-contamination risk. |
| **JVM / Kotlin / Scala** | CFR, Vineflower, Procyon, Fernflower | In-house Rust decompiler is the default; CFR, Vineflower, Procyon, and jadx remain available as `--backend`. Adds ProGuard/R8 mapping replay and obfuscator peel in the same pass. |
| **Android (DEX)** | jadx, dex2jar + a Java decompiler | Direct DEX-to-Java without the dex2jar hop; APK signature v1-v3 verification and RASP detection in one binary. Method-body recovery is partial (~43% of all methods, ~65% of comparable non-synthetic methods). |
| **.NET / CIL** | ILSpy, dnSpy, de4dot | In-house CIL to C#/F#/VB plus an actively maintained obfuscator reverser; de4dot has been unmaintained since 2020. ILSpy, dnSpy, and de4dot stay available as `--backend`. |
| **Lua** | unluac, luadec | Covers 5.1-5.4, LuaJIT, Luau, and GLua in one decoder, plus 11 obfuscator reversers (MoonSec, Ironbrew2). unluac is the maturity benchmark for stock `luac`. |
| **Ruby** | none (no FOSS YARV/mruby decompiler) | Decompiles MRI/YARV 1.9-3.4 and mruby. No comparable open-source Ruby decompiler exists. |
| **BEAM (Erlang / Elixir)** | `beam_disasm` (disassembly only) | Lifts BEAM chunks to Core Erlang and recovers Elixir from the `Dbgi` chunk. The standard tooling disassembles but does not reconstruct source. |
| **PHP** | none for modern bytecode (ionCube/SourceGuardian are commercial) | Structural decode of ionCube/SourceGuardian/Zend Guard and Phar archives. No maintained FOSS PHP-bytecode decompiler exists. |
| **WebAssembly** | wasm-decompile, wasm2c, wasm-tools | Lifts to typed Rust, TypeScript, WAT, or C with DWARF recovery and five obfuscator reversers, rather than emitting a single fixed target. |
| **JavaScript / TypeScript** | webcrack, synchrony, REstringer | obfuscator.io (9 stages), JS-Confuser, Jscrambler, esoteric encoders, V8/Bytenode, and 10 bundlers with scope-aware renaming and source-map reconstruction. |
| **ActionScript 3 / Flash** | JPEXS Free Flash Decompiler (FFDec) | FFDec is the mature, full-graph SWF and AS3 decompiler and remains the better tool for deep Flash work. `disrobe` parses SWF and disassembles ABC bytecode as part of the unified chain; this path is local-corpus only and not CI-validated. |

## Unpacking and extraction (byte-exact where possible)

| Ecosystem | Established tools | Where `disrobe` differs |
|---|---|---|
| **Python freezers** | pyinstxtractor (PyInstaller only), per-freezer scripts | PyInstaller, cx_Freeze, py2exe, PyOxidizer, shiv, pex, Briefcase, and Nuitka unpacked by one tool, then handed to the decompiler. Nuitka onefile/standalone is byte-exact; its native bodies are lossy. |
| **Python protectors** | none maintained for current PyArmor | PyArmor v6-v9-pro static-key recovery (70 of 72 real-corpus samples) and SourceDefender `.pye` decryption. These are commercial protectors with no current FOSS reverser. |
| **Native packers** | UPX (unpacks UPX only); per-packer one-off scripts | First general-purpose FOSS unpacker for the tier: UPX, kkrunchy, NSPack, Petite, MPRESS, FSG, MEW, ASPack, PECompact, and Yoda's via clean-room decoders and an in-house x86 stub emulator, with per-fixture byte-recovery scores. |
| **React Native Hermes** | hermes-dec, hbctool | Bytecode v60-v96, validated locally on a 66 MiB production bundle (122,633 functions lifted, no parse or lift failures). |
| **Containers and archives** | unsquashfs, 7-Zip, asar, format-specific CLIs | Detects 45 container/archive formats and fully extracts 26 in-tree (ZIP, tar, 7z, `.deb`, `.rpm`, MSI, NSIS, Docker/OCI, ...) with universal zip-slip and decompression-bomb guards. |

## Native and AOT-compiled (symbols and demangling, not source)

These targets compile to machine code, so function bodies are not recoverable as source. The deliverable is unpacking, symbol and metadata recovery, and demangling that gives a disassembler cleaner input.

| Ecosystem | Established tools | Where `disrobe` differs |
|---|---|---|
| **Native (PE/ELF/Mach-O)** | Ghidra, IDA, Binary Ninja | Not a competitor on raw decompilation. The unpack, symbol-recovery, and chain-detect layer that feeds those tools cleaner input. DWARF/PDB/STABS across x86, ARM, RISC-V, MIPS, PowerPC, SPARC, and eBPF. |
| **Go** | GoReSym, redress | Symbol recovery plus garble undo and embedded-FS walking; `pclntab` eras go1.2 through go1.26, with type-name resolution gated above 85%. |
| **Swift / Objective-C** | class-dump, `swift-demangle` | Mach-O class-dump with SwiftConfidential and SwiftShield rename-undo in one pass. Bodies stay native; the output is the interface and restored names. |
| **Flutter (Dart AOT)** | blutter, doldrums | Parses the AOT snapshot string table for class and method names and library URIs. ARM64 AOT erases bodies, so counts are reported with no body recovery, at the symbol level blutter also targets. |
| **Nim / Zig / Crystal** | binary disassemblers, language demanglers | Detect, demangle, and recover symbols and metadata from each binary's own symtab and type table. Source is not recoverable. |

## Where `disrobe` is not the right tool

- Deep, interactive Flash reversing: use **FFDec**.
- Full native decompilation to C: use **Ghidra**, **IDA**, or **Binary Ninja**. `disrobe` prepares input for them; it does not replace them.
- Devirtualizing VMProtect, Themida, or Enigma: `disrobe` detects the protector and carves intact sections, but does not lift virtualized bytecode back to source.
- Any AOT-compiled language (Nim, Zig, Crystal, Flutter Dart, Swift bodies): source bodies are gone at compile time; demangling and symbol recovery are the ceiling, the same ceiling every tool faces.
