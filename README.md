# disrobe

[![CI](https://github.com/1-3-7/disrobe/actions/workflows/ci.yml/badge.svg)](https://github.com/1-3-7/disrobe/actions/workflows/ci.yml)
[![Docs](https://github.com/1-3-7/disrobe/actions/workflows/docs.yml/badge.svg)](https://1-3-7.github.io/disrobe/)
[![Release](https://img.shields.io/github/v/release/1-3-7/disrobe?sort=semver)](https://github.com/1-3-7/disrobe/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE-APACHE)
[![Rust 1.95+](https://img.shields.io/badge/rust-1.95%2B-orange.svg)](https://www.rust-lang.org)

**A deterministic multi-language decompiler and deobfuscator suite written in Rust.**

`disrobe` peels the bytecode, packers, freezers, and protectors stacked across the software supply chain: Python (1.0-3.15), JavaScript and TypeScript, WebAssembly, JVM and Android, .NET and native AOT, native PE/ELF/Mach-O, React Native Hermes, Flutter Dart AOT, Go, Lua, PHP, Ruby, Erlang and Elixir, Swift and Objective-C, AS3, Nim, Zig, Crystal, Perl, R, Tcl, and Haxe.

Full documentation: **[1-3-7.github.io/disrobe](https://1-3-7.github.io/disrobe/)**

```sh
$ disrobe auto suspect.exe --out recovered/
# detected: PE -> UPX -> rust-demangle
# stage 01-upx        ok    (byte-identical unpack, 1.18 MiB in 9 ms)
# stage 02-demangle   ok    (Rust + C++ symbols demangled, 0 unresolved)
# final               ok    -> recovered/final/
```

## What it does

`disrobe` strips obfuscation, freezing, packing, and protection off a binary so you can read what it does without running it. It is built for forensic and recovery work, where the same input must give the same output on every machine and every run. Nothing in the decompile path is statistical, so there is no model to drift and nothing to retrain. The build is one static binary with no JVM, Python, or Docker dependency: `cargo build --release`, then run it headlessly in CI.

The Python, JVM/Kotlin, Dalvik, .NET CIL, and WebAssembly decompilers are written in Rust and ship as the product. CFR, Vineflower, Procyon, jadx, ILSpy, dnSpy, and de4dot are optional `--backend` fallbacks, off by default. On native PE/ELF/Mach-O it does not attempt raw decompilation; it unpacks, recovers symbols, and detects packer chains, then hands Ghidra, IDA, or Binary Ninja cleaner input.

Every artifact is content-addressed and persisted as a `.dr` envelope (rkyv payload, postcard sidecar, BLAKE3 root), so cache hits are byte-identical and chains compose offline. Recovery is measured against an independent reference, not the tool's own output: recovered Python is recompiled on the matching interpreter and compared opcode-for-opcode, and unpacked bytes are compared to the original. Lossy results carry their measured score under `SEMANTIC`, `PARTIAL`, or `SKELETON` and are never rounded up; what the tool cannot fully recover is reported as detect-only. Any pass can also emit an `--llm` metadata sidecar (call graph, types, control flow, capability surface, provenance).

## Supported languages and formats

| Ecosystem | What `disrobe` does |
|---|---|
| **Python bytecode** | In-house Rust decompiler for CPython (modern gate 3.6-3.15, support banner 1.0-3.15), PyPy, MicroPython `.mpy`, Jython, IronPython, Brython. `match`, walrus, f/t-strings (PEP 750), exception groups, PEP 695/696/709 recompile-verified. |
| **Python freezers** | PyInstaller 2.x-6.20+, Nuitka (onefile/standalone/module/wheel; byte-exact unpack, native bodies are lossy), cx_Freeze, py2exe, PyOxidizer, shiv, pex, Briefcase, SourceDefender `.pye` (in-house AES-256-CTR + BLAKE2b decrypt, real-corpus validated). |
| **Python protectors** | PyArmor v6-v9-pro (default + super + no-wrap; 70/72 real-corpus recoveries) and 14 source obfuscators (Hyperion, Kramer, Berserker, BlankOBF, oxyry, pyminifier, ...) via an AST-evaluator backend. |
| **JavaScript / TypeScript** | obfuscator.io (full 9-stage), JS-Confuser, Jscrambler (36 transforms), esoteric encoders, V8/Bytenode, and 10 bundlers (webpack, Vite, Rollup, esbuild, Parcel, Rolldown, ...) with scope-aware renaming and source-map reconstruction. |
| **WebAssembly** | Parse + lift to Rust, TypeScript, WAT, or C. GC, component model, threads, SIMD, tail-call, memory64, DWARF. 5 obfuscator reversers. |
| **JVM / Kotlin / Scala / Android** | In-house Rust decompilers for classfile 1.0.2-25 and DEX 1.0-16 as the default; ProGuard/R8 mapping replay; Zelix/Allatori/Stringer/DashO/DexGuard detect + structural peel. APK sig v1-v3 verify, RASP detect. Optional `--backend cfr|vineflower|procyon|jadx`. |
| **.NET / CIL** | In-house CIL to C#/F#/VB; full PE + CLR + table-stream parser, R2R + native-AOT classify, 20+ obfuscator reversers (ConfuserEx2, .NET Reactor, Eazfuscator, ...). Optional `--backend ilspy|dnspy|de4dot`. |
| **Native (PE/ELF/Mach-O/COFF)** | DWARF/PDB/STABS across x86/ARM/RISC-V/MIPS/PowerPC/SPARC/eBPF; Rust + C++ demangle + restoration. The unpack + symbol-recovery + chain-detect layer that feeds Ghidra/IDA cleaner input. |
| **Native packers** | UPX (byte-identical), kkrunchy classic (byte-exact), NSPack, Petite, MPRESS, FSG, MEW, ASPack, PECompact, Yoda's via clean-room decoders + an in-house x86 stub emulator. Detect + carve on the virtualized tier (VMProtect, Themida, Enigma, ...). |
| **Go** | GoReSym + redress symbol recovery, garble undo, embedded-FS walker, pclntab 1.2-1.26 (~557 type names resolved on 1.26.3 in a local run; CI gates the resolution rate at >=85%). |
| **Nim / Zig / Crystal** | Detect + name-demangle + symbol/metadata recovery from each binary's own symtab and type table. Source is not recoverable (compiled languages); demangling is the deliverable. |
| **Perl / R / Tcl / Haxe** | Tcl starkit byte-identical extract, R `.rds` round-trip, Perl `B::Concise` op-tree, Haxe cross-target detect + route. |
| **Lua** | 5.1-5.4, LuaJIT 2.0/2.1, Luau, GLua, and 11 obfuscators including MoonSec v1-v3 and Ironbrew2. |
| **Shell** | PowerShell Invoke-Obfuscation levels 1-6, Bashfuscator, batch, VBA p-code (detect-only header parse). |
| **PHP / Ruby / BEAM** | ionCube/SourceGuardian/Zend Guard structural decode + Phar; MRI/YARV 1.9-3.4 + mruby decompile; BEAM chunk parse + Core Erlang lift + Elixir `Dbgi`. |
| **React Native Hermes** | Bytecode v60-v96, validated locally on a non-redistributable 66 MiB Discord bundle: 122,633 functions, 0 errors. |
| **Flutter / Swift / AS3** | Dart AOT snapshot parser (class/method names and library URIs from the snapshot string table; ARM64 AOT erases bodies, so counts are reported raw with no body recovery); Mach-O class-dump + SwiftConfidential/SwiftShield rename-undo; SWF + ABC bytecode disasm (local corpus only; not CI-validated). |
| **Python pickle** | Static disasm + symbolic-VM trace + safety grading + polyglot + ML-model detection. Never unpickles. |
| **Containers** | 26 formats (ZIP/tar/7z/`.deb`/`.rpm`/`.iso`/MSI/NSIS/Docker/OCI/SquashFS/...) with auto-detect, chaining, and universal zip-slip + bomb guards. |

## Comparison

| Ecosystem | Leading tools | Where `disrobe` differs |
|---|---|---|
| **Python** | pycdc, pylingual, uncompyle6, decompyle3, pychd | Spans 3.6-3.15 in one engine with in-band recompile-equivalence; deterministic, no LLM, no benchmark contamination. uncompyle6 stops at 3.8, decompyle3 ~3.9; the ML-based tools are non-reproducible and contamination-flagged. |
| **JVM / Android** | CFR, Vineflower, Procyon, jadx | In-house Rust decompiler is the default (those become optional `--backend`s); adds chain auto-detect, `.dr` envelopes, and APK sig verify in one binary. |
| **.NET / CIL** | ILSpy, dnSpy, de4dot | In-house CIL to C#/F#/VB plus a modern obfuscator-reverser fork; de4dot froze in 2020. Deterministic `.dr` output. |
| **Native** | Ghidra, IDA, Binary Ninja | Not a competitor on raw decompilation; the unpack + symbol-recovery + chain-detect layer that feeds them cleaner input. |
| **Native packers** | per-packer one-off scripts; UPX only unpacks UPX | First general-purpose FOSS unpacker for the tier, with an in-house x86 stub emulator and per-fixture byte-recovery scores. |
| **JS** | webcrack, synchrony, REstringer | Full obfuscator.io + JS-Confuser + Jscrambler + 10 bundlers with source-map reconstruction, behind a deterministic codegen. |
| **WASM** | wasm-decompile, wasm2c, wasm-tools | The only one lifting to typed Rust/TS/WAT/C with DWARF recovery and obfuscator reversers. |

Full per-ecosystem comparison tables (freezers, protectors, Lua, shell, PHP, Ruby, BEAM, Swift, Flash, Hermes, Flutter, containers) are in the [docs](https://1-3-7.github.io/disrobe/).

## Limits

`.class`, `.dex`, and CIL erase local names, generics, comments, and exact formatting; recovery is structurally faithful but never byte-identical (Dalvik body ceiling ~60-75%). Nuitka onefile/standalone unpack is byte-exact, but Nuitka compiles Python to C to native, so recovered function bodies are skeleton-to-partial (~30-50%) while symbols and constants recover cleanly. Nim/Zig/Crystal and Flutter Dart AOT have no source-body recovery; demangling, symbol, name, and metadata recovery from the binary's own tables is the deliverable.

VMProtect, Themida, Enigma, and the commercial tier are detect plus section-carve only.

## Install

Prebuilt binaries from the Releases tab, or build from source.

### Prebuilt binaries (recommended)

Download from the [Releases page](https://github.com/1-3-7/disrobe/releases). Windows, Linux (glibc + musl), and macOS, each for x86-64 and ARM64, with `SHA256SUMS` plus cosign and minisign signatures. Verify, extract, and drop `disrobe` (`disrobe.exe` on Windows) on your `PATH`.

```sh
sha256sum -c SHA256SUMS
```

### Build from source

Requires Rust 1.95+ stable. That is the only build dependency.

```sh
git clone https://github.com/1-3-7/disrobe
cd disrobe
cargo build --release
./target/release/disrobe doctor   # optional: probe ~50 external tools
```

A release build takes ~4-6 minutes on commodity hardware.

## Quick start

```sh
disrobe auto suspect.exe --out recovered/            # auto-detect + chain the whole pipeline
disrobe py decompile module.pyc --out recovered/
disrobe pyinstaller extract onefile.exe --out out/
disrobe pyarmor unpack protected.py --out out/       # add --allow-dynamic only on trusted samples
disrobe js deob bundle.min.js --out clean.js
disrobe js unbundle app.bundle.js --out src/
disrobe wasm decompile module.wasm --target rust --out lifted.rs
disrobe jvm decompile app.apk --out src/             # in-house Dalvik decompiler is the default
disrobe dotnet decompile App.dll --out src/          # in-house CIL decompiler is the default
disrobe native unpack packed.exe --out unpacked.bin
disrobe go recover app --out symbols.json
disrobe lua decompile script.luac --out script.lua
disrobe hermes lift index.android.bundle --out surface/
```

`disrobe auto` fingerprints the input and chains the full pipeline in one call (`PE -> UPX -> rust-demangle`, `APK -> dex -> Java`, `PyInstaller -> PyArmor -> .pyc decompile`). With `--capture-stages`, stage outputs land in `out/01-*/`, `out/02-*/`, ..., `out/final/`. Discover the full surface with `disrobe --help`, drill into any subcommand with `disrobe <pass> --help`, list passes with `disrobe passes`, and list optional external tools with `disrobe install --list`.

## The five-rung IR ladder

Every artifact climbs the same intermediate-representation ladder. This is what lets passes from different ecosystems compose through a shared `.dr` envelope.

```text
   Raw  -->  Disasm  -->  MIR  -->  HIR  -->  Surface
   bytes     opcodes      mid       high      source
```

Unpacking and decryption passes operate at **Raw**; byte-identical unpack lives here. Disassembly produces **Disasm**. Decompilers do their structural work at **MIR** and **HIR**, then render **Surface**. For Python, the MIR pre-pass reconstructs nested constructs from the 3.11+ exception table before the instruction walk, and the Surface output is recompiled and verified opcode-for-opcode. See the [architecture docs](https://1-3-7.github.io/disrobe/architecture.html) for the full model.

## Common flags

| Flag | Effect |
|---|---|
| `--json` / `--ndjson` / `--sarif` | Structured output (SARIF 2.1.0 for GitHub code scanning) |
| `--llm` | Emit the structured metadata sidecar (18 categories, 4 packs) for LLM consumers |
| `--backend <tool>` | Select an optional external decompiler instead of the in-house default |
| `--dry-run` | Report what would happen, write nothing |
| `--no-cache` | Bypass the `.dr` envelope cache (output is identical either way) |
| `--seed <N>` | RNG seed for any non-deterministic backend |
| `--i-have-authorization` | Gate flag for grey-zone commercial protectors and the decryption-keys metadata |

## Safety posture

By default `disrobe` does not execute the sample. Every default path is pure static analysis. The pickle suite is symbolic and never unpickles. The only code-execution paths (PyArmor v6/v7 dynamic-hook, BCC native lift) sit behind explicit `--allow-dynamic` and `--allow-bcc` flags with a watchdog; run those inside a sandbox. The parsing surface is hardened. See [Forensics and malware-safety posture](https://1-3-7.github.io/disrobe/forensics-safety.html) and the full [threat model](https://1-3-7.github.io/disrobe/threat-model.html).

## Documentation

The full docs site lives at **[1-3-7.github.io/disrobe](https://1-3-7.github.io/disrobe/)**: architecture, the IR ladder, the chain runner, per-language guides, the complete CLI reference, and the safety posture. The book source is under [`docs/`](docs/).

## Legal

Decompilation for security research, interoperability, and recovery of your own source is permitted in most jurisdictions (US DMCA Sec. 1201(f), EU Software Directive 2009/24/EC art. 6, UK CDPA Sec. 50B/50BA, and equivalents in CA/AU/JP). The full posture with statutory citations and a takedown channel is in [LEGAL.md](LEGAL.md).

> [!IMPORTANT]
> Grey-zone commercial protectors are gated behind the explicit `--i-have-authorization` flag and never run otherwise. Use is your responsibility per the statutory framing above.

## Contributing

Contributions welcome under the [Contributor Covenant 2.1](.github/CONTRIBUTING.md). For security issues, open a [private advisory](https://github.com/1-3-7/disrobe/security/advisories/new) rather than a public issue. See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE-APACHE](LICENSE-APACHE) and [NOTICE](NOTICE).
