# `disrobe`

[![CI](https://github.com/1-3-7/disrobe/actions/workflows/ci.yml/badge.svg)](https://github.com/1-3-7/disrobe/actions/workflows/ci.yml)
[![Docs](https://github.com/1-3-7/disrobe/actions/workflows/docs.yml/badge.svg)](https://1-3-7.github.io/disrobe/)
[![Release](https://img.shields.io/github/v/release/1-3-7/disrobe?sort=semver)](https://github.com/1-3-7/disrobe/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE-APACHE)
[![Rust 1.95+](https://img.shields.io/badge/rust-1.95%2B-orange.svg)](https://www.rust-lang.org)

**Strip the obfuscation, read the source.   A deterministic deobfuscator and decompiler for the modern stack, in a single Rust binary.**

One tool covers Python (1.0-3.15), JavaScript/TypeScript, WebAssembly, JVM + Android, .NET + native AOT, native PE/ELF/Mach-O, React Native Hermes, Flutter Dart AOT, Lua/LuaJIT/Luau, PHP, Ruby, Erlang/Elixir, Swift/Objective-C, AS3/Flash, and the 22 native packers commonly stacked on top of them - pyc decompiler, PyArmor unpacker, PyInstaller/Nuitka extractor, dex-to-Java, UPX unpacker, JS unbundler, WASM lifter, all in one place.

Full documentation: **[1-3-7.github.io/disrobe](https://1-3-7.github.io/disrobe/)**

```sh
$ disrobe auto suspect.exe --out recovered/
# detected: PE -> UPX -> rust-demangle
# stage 01-upx        ok    (byte-identical unpack, 1.18 MiB in 9 ms)
# stage 02-demangle   ok    (Rust + C++ symbols demangled, 0 unresolved)
# final               ok    -> recovered/final/
```

## What only `disrobe` does

A few things `disrobe` does that no other tool, free or commercial, does at all:

- **Decompiles every CPython from 1.0 to 3.15 - deterministically, in one engine.** Nothing else spans this range: uncompyle6 stops at 3.8, decompyle3 around 3.9, pycdc is partial and undocumented on modern releases, and the ML-based decompilers aren't reproducible. `disrobe` is the first to recover the newest syntax - `match`, t-strings (PEP 750), exception groups, PEP 695/696 generics - and it recompiles every result on the matching interpreter and diffs it opcode-for-opcode. Construct-level recovery is **100%, recompile-equivalent, across 3.8 through 3.15** (every construct recompiles to equivalent bytecode on its own interpreter); the 1.0-3.7 legacy range is climbing toward it.
- **Covers the entire modern stack in a single static binary.** Python, JavaScript/TypeScript, WebAssembly, JVM/Android, .NET, native PE/ELF/Mach-O, Go, Lua, PHP, Ruby, BEAM, Swift, AS3, Hermes, Flutter - one `cargo build`, no JVM or Python runtime to install. No other tool, and no short stack of them, spans these in one place.
- **Produces deterministic, evidence-grade output.** No model anywhere in the decompile path: the same input yields byte-identical output on every machine, content-addressed in a `.dr` envelope. A decompile becomes a forensic baseline and a diff target - something neither Ghidra/IDA nor any ML decompiler is built to give you.

## What is `disrobe`

`disrobe` strips the obfuscation, freezing, packing, and protection layers off a binary so you can read what it actually does - without executing it. It is built for forensic and recovery work where reproducibility matters:

- **Deterministic.** No model anywhere in the decompile path. Same input, same output, every machine, every run - so the output is a usable evidence and diff baseline.
- **Single static binary.** No JVM, no Python runtime, no Docker. One `cargo build --release`. Drops into CI headlessly.
- **Content-addressed.** Every artifact persists as a `.dr` envelope (rkyv hot payload + postcard cold sidecar + BLAKE3 root). Cache hits are byte-identical; chains compose offline.
- **Honest.** Every decompilation is recompiled on its matching runtime (if applicable) and compared opcode-for-opcode. Recovery that is not perfect is labelled, never faked. Commercial-tier packers `disrobe` cannot unpack are reported as detect-only by design.
- **Agent-ready.** Any pass can emit a structured `--llm` metadata sidecar (call graph, types, control flow, capability surface, decompile provenance) so a coding agent reasons about recovered code without re-deriving it.

## Supported languages and formats

Every cell is backed by a fixture in `corpus/` and an integration test in `crates/disrobe-cli/tests/` - nothing is aspirational.

| Ecosystem | What `disrobe` does |
|---|---|
| **Python bytecode** | Per-version disassembler + in-house decompiler for CPython 1.0-3.15, PyPy, MicroPython `.mpy` v0-v6, Jython, IronPython, Brython. `match`, walrus, f/t-strings (PEP 750), exception groups, PEP 695/696/709 round-trip-verified. |
| **Python freezers** | PyInstaller 2.x-6.20+, Nuitka (onefile/standalone/module/wheel), cx_Freeze, py2exe, PyOxidizer, shiv, pex, Briefcase, SourceDefender `.pye` (in-house AES-256-CTR + BLAKE2b decrypt, real-corpus validated). |
| **Python protectors** | PyArmor v6-v9-pro (default + super + no-wrap) and 14 source obfuscators (Hyperion, Kramer, Berserker, BlankOBF, oxyry, pyminifier, ...) with an AST-evaluator backend. |
| **JavaScript / TypeScript** | obfuscator.io (full 9-stage), JS-Confuser, Jscrambler (36 transforms), esoteric encoders, V8/Bytenode, and 10 bundlers (webpack, Vite, Rollup, esbuild, Parcel, Rolldown, ...) with scope-aware renaming. |
| **WebAssembly** | Parse + lift to Rust, TypeScript, WAT, or C. GC, component model, threads, SIMD, tail-call, memory64, DWARF. 5 obfuscator reversers. |
| **JVM / Kotlin / Scala / Android** | Classfile 1.0.2-25, DEX 1.0-16, ProGuard/R8 mapping replay, Zelix/Allatori/Stringer/DashO/DexGuard detect + structural peel (string recovery only when the class ships its own embedded decrypt stub). Headless CFR, Vineflower, Procyon, jadx. |
| **.NET / CIL** | Full PE + CLR + table-stream parser, R2R header detect + flag classify, native-AOT runtime/format classify, CIL to C#/F#/VB, 20+ obfuscator reversers (ConfuserEx2, .NET Reactor, Eazfuscator, ...). Headless ILSpy, dnSpy, de4dot. |
| **Native (PE/ELF/Mach-O/COFF)** | DWARF/PDB/STABS across x86/ARM/RISC-V/MIPS/PowerPC/SPARC/eBPF; Rust + C++ demangle + restoration. The unpack + symbol-recovery + chain-detect layer that feeds Ghidra/IDA cleaner input. |
| **Native packers** | UPX (byte-identical), MPRESS, NSPack, FSG, Petite, kkrunchy, MEW via clean-room decoders; honest detect-only on the commercial tier (VMProtect, Themida, Enigma, ...). |
| **Go** | GoReSym + redress symbol recovery, garble undo, embedded-FS walker, pclntab 1.2-1.26 (557/557 type-name resolution on 1.26.3, locally reproducible; binary exceeds the committed-fixture budget). |
| **Lua** | 5.1-5.4, LuaJIT 2.0/2.1, Luau, GLua, and 11 obfuscators including MoonSec v1-v3 and Ironbrew2. |
| **Shell** | PowerShell Invoke-Obfuscation levels 1-6, Bashfuscator, batch, VBA p-code. |
| **PHP / Ruby / BEAM** | ionCube/SourceGuardian/Zend Guard structural decode + Phar; MRI/YARV 1.9-3.4 + mruby decompile; BEAM chunk parse + Core Erlang lift + Elixir `Dbgi`. |
| **React Native Hermes** | Bytecode v60-v96, validated locally on a non-redistributable 66 MiB Discord bundle: 122,633 functions, 0 errors. |
| **Flutter / Swift / AS3** | Dart AOT snapshot parser; Mach-O class-dump + SwiftConfidential/SwiftShield rename-undo; SWF + ABC bytecode disasm (local corpus only; not CI-validated). |
| **Python pickle** | Static disasm + symbolic-VM trace + safety grading + polyglot + ML-model detection. Never unpickles. |
| **Containers** | 26 formats (ZIP/tar/7z/`.deb`/`.rpm`/`.iso`/MSI/NSIS/Docker/OCI/SquashFS/...) with auto-detect, chaining, and universal zip-slip + bomb guards. |

## Comparison
<details>
<summary>Per-ecosystem comparison tables (decompilers, freezers, protectors, JS, WASM, JVM, .NET, native, packers, Go, Lua, shell, PHP, Ruby, BEAM, Swift, Flash, Hermes, Flutter, containers)</summary>

### Python freezers

| Capability | pyinstxtractor(-ng) | nuitka-extractor | `disrobe` |
|---|---|---|---|
| PyInstaller 2.x-6.x | y | n | y (6.20+; live E2E, fixture too large to commit) |
| Nuitka onefile/standalone, `as_archive`, signed-PE, wheel | n | partial | y |
| cx_Freeze, py2exe, PyOxidizer, shiv, pex, Briefcase | n | n | y (briefcase/shiv/zipapp real-tested; cx_Freeze/py2exe/pex regen-gated) |
| SourceDefender `.pye` | n | n | y (in-house decrypt, real-corpus validated to source) |
| Auto-chain into PyArmor + `.pyc` decompile | n | n | y |
| License | GPL-3.0 | varies | Apache-2.0 |

### Python protectors

| Capability | PyArmor-Unpacker | Static-Unpack-1shot | PyArmor-Deobfuscator | `disrobe` |
|---|---|---|---|---|
| PyArmor v6/v7 | y | y | partial | y |
| PyArmor v8 / v9-pro | n | partial | n | y (70/72 real-corpus source recovery) |
| Fully static (no `marshal.loads` injection) | partial | y | y | y |
| 14 obfuscators + AST-evaluator backend | n | n | n | y |
| License | GPL-3.0 | GPL-3.0 | MIT | Apache-2.0 |

### JavaScript / TypeScript

| Capability | webcrack | synchrony | REstringer | `disrobe` |
|---|---|---|---|---|
| obfuscator.io (full 9-stage) | y | y (older) | y | y |
| js-confuser / Jscrambler (36x12) | partial | n | partial | y |
| Esoteric encoders / V8/Bytenode | partial | n | partial | y |
| Unbundle 10 bundlers | partial | n | n | y |
| License | MIT | GPL-3.0 | MIT | Apache-2.0 |

### WebAssembly

| Capability | wasm-decompile | wasm2c | wasm-tools | `disrobe` |
|---|---|---|---|---|
| Lift to C / Rust / TypeScript / WAT | C only | raw C | WAT only | all four |
| GC, component model, threads, SIMD, memory64 | partial | partial | y | y |
| DWARF recovery / 5 obfuscator reversers | n | n | n | y |
| License | Apache-2.0 | Apache-2.0 | Apache-2.0/MIT | Apache-2.0 |

### JVM (Java / Kotlin / Scala)

| Capability | CFR | Vineflower | Procyon | `disrobe` |
|---|---|---|---|---|
| Classfile 1.0.2-25 | y | y | y | y (wraps + own validator) |
| Records, sealed, pattern matching | partial | y | partial | y |
| Obfuscator reversers (Zelix, Allatori, Stringer, DashO) | n | n | n | detect + structural peel (stub-emulation string recovery) |
| ProGuard/R8 mapping replay / headless wrap | n | n | n | y |
| License | MIT | Apache-2.0 | Apache-2.0 | Apache-2.0 |

### Android (DEX / APK)

| Capability | jadx | Apktool | dex2jar | `disrobe` |
|---|---|---|---|---|
| DEX 1.0-16 to Java | y | n | JAR only | y (wraps jadx) |
| APK resource decode | partial | y | n | y (wraps Apktool) |
| Smali round-trip / DexGuard reverser | y / n | y / n | n | y / detect + structural |
| Chain APK -> dex -> jadx + smali + manifest | partial | n | n | y |
| License | Apache-2.0 | Apache-2.0 | Apache-2.0 | Apache-2.0 |

### .NET / CIL

| Capability | ILSpy | dnSpyEx | de4dot | `disrobe` |
|---|---|---|---|---|
| CIL -> C# decompile | y | y | n | y (wraps ILSpy) |
| 20+ obfuscator reversers | n | n | y (frozen 2020) | y (modern fork + own) |
| R2R lift / native AOT symbol recovery | partial / n | partial / n | n | y / partial |
| Deterministic `.dr` envelope | n | n | n | y |
| License | MIT | GPL-3.0 | GPL-3.0 | Apache-2.0 |

### Native (PE / ELF / Mach-O / COFF)

`disrobe` does **not** compete with Ghidra/IDA/Binary Ninja for raw decompilation - it is the unpack + symbol-recovery + chain-detect layer that feeds them cleaner input.

| Capability | Ghidra | IDA Pro | radare2 | `disrobe` |
|---|---|---|---|---|
| Full decompiler to pseudo-C | y | y | partial | n (feeds these) |
| Multi-format parse + multi-arch disasm | y | y | y | y |
| Rust + C++ demangle + restoration | partial | partial | partial | y (4172 Rust + 312 C++ on real ripgrep/git) |
| Single binary, no JVM/Python, headless CI | n | n | partial | y |
| License | Apache-2.0 | commercial | LGPL/GPL | Apache-2.0 |

### Native packers

No FOSS toolkit covers this range; UPX only unpacks UPX, de4dot only .NET, the rest are per-packer one-off scripts. `disrobe` is the first general-purpose FOSS unpacker for the tier, with per-fixture honest scores in `corpus/native/packers/MANIFEST.toml`.

| Packer | `disrobe` |
|---|---|
| UPX | byte-identical, in-house clean-room NRV2B (no `upx -d`) |
| MPRESS (clean-room LZMA1 split-nibble) | 91.58% byte-recovery |
| NSPack (adaptive range coder) | content 98.6-99.3%; whole-file 50-94% |
| FSG | 2/3 byte-identical |
| Petite (x86 stub emulator) | 97.8% content on hello32 |
| kkrunchy | 17.8% via in-house CCA range-decoder; byte-identical needs the x86 stub emulator |
| MEW (emulated dynamic-fetch) | 91.8% / 95.0% / 64.5% across 3 fixtures |
| Commercial tier (VMProtect, Themida, Enigma, +15) | honest detect-only by design |

### Go

| Capability | GoReSym | redress | garble-undo | `disrobe` |
|---|---|---|---|---|
| Stripped symbol recovery | y (<=1.24) | y | n | y (1.2-1.26, 557/557 on 1.26.3, locally reproducible) |
| pclntab 1.2-1.25 / embedded-FS walker | y / n | y / n | n | y / y |
| Garble undo / UPX-on-Go auto-chain | n | n | partial | partial / y |
| License | MIT | AGPL-3.0 | - | Apache-2.0 |

### Lua / LuaJIT / Luau

| Capability | unluac | LuaDec | luajit-decompiler-v2 | `disrobe` |
|---|---|---|---|---|
| Lua 5.1-5.4 | y | partial | n | y (per-dialect lifters) |
| LuaJIT 2.0/2.1 / Luau | n | n | y / n | y |
| 11 obfuscators (MoonSec, Ironbrew2, ...) | n | n | n | partial (WeAreDevs reversed; VM-walled others detected) |
| License | MIT | MIT | MIT | Apache-2.0 |

### Shell / PowerShell / Batch / VBA

| Capability | Revoke-Obfuscation | Invoke-Deobfuscation | `disrobe` |
|---|---|---|---|
| Invoke-Obfuscation levels 1-6 | detect-only | y | y |
| Bash/Bashfuscator round-trip / batch / VBA decompress | n | n | y |
| VBA p-code disasm | n | n | honest detect-only (header parse; opcode-table is the pcodedmp-scope wall) |
| License | Apache-2.0 | MIT | Apache-2.0 |

### PHP

The FOSS landscape is essentially nothing; the dominant tools are paid server-side services.

| Capability | DeZender (paid) | php-decode | `disrobe` |
|---|---|---|---|
| ionCube / SourceGuardian / Zend Guard structural decode | y (server-side) | partial | y (offline) |
| Phar walker / FOPO unwrap / token re-emit (no upload) | n | partial | y |
| License | commercial | varies | Apache-2.0 |

### Ruby / BEAM / Swift / Flash / Hermes / Flutter / Containers

| Ecosystem | Field | `disrobe` edge |
|---|---|---|
| **Ruby** | yarvdis (disasm only), rb-decompile (abandoned) | MRI/YARV 1.9-3.4 + mruby **source-level decompile** |
| **BEAM** | beam_lib, BeamFile | Core Erlang lift + Elixir `Dbgi` + `.ez` extract |
| **Swift / Obj-C** | class-dump (2013), Hopper (paid) | Swift + Obj-C class-dump, SwiftConfidential/SwiftShield rename-undo, FairPlay detect-only |
| **AS3 / Flash** | JPEXS | parser + disasm, feeds JPEXS (full source wrap planned; local corpus only, not CI-validated) |
| **Hermes** | hbctool (<=v84), hermes-dec | v60-v96, decompile, validated locally on a non-redistributable 66 MiB Discord bundle |
| **Flutter** | blutter (Android-only), reFlutter | Dart snapshot parser, single-binary CLI, validated on real `rustdesk` `libapp.so` |
| **Containers** | 7-Zip, libarchive | 26 kinds, auto-detect + chain through nested layers, bomb guards |

</details>


## Install

Prebuilt binaries from the Releases tab, or build from source. See below.

### Prebuilt binaries (recommended)

Download from the [Releases page](https://github.com/1-3-7/disrobe/releases) - Windows, Linux (glibc + musl), and macOS, each for x86-64 and ARM64, with `SHA256SUMS` plus cosign and minisign signatures. Verify, extract, and drop `disrobe` (`disrobe.exe` on Windows) on your `PATH`.

```sh
sha256sum -c SHA256SUMS
```

### Build from source

Requires Rust 1.95+ stable; that is the only build dependency.

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
disrobe jvm decompile app.apk --backend jadx --out src/
disrobe dotnet decompile App.dll --backend ilspy --out src/
disrobe native unpack packed.exe --out unpacked.bin
disrobe go recover app --out symbols.json
disrobe lua decompile script.luac --out script.lua
disrobe hermes lift index.android.bundle --out surface/
```

`disrobe auto` fingerprints the input and chains the full pipeline in one call (`PE -> UPX -> rust-demangle`, `APK -> dex -> jadx + smali`, `PyInstaller -> PyArmor -> .pyc decompile`); with `--capture-stages`, stage outputs land in `out/01-*/`, `out/02-*/`, ..., `out/final/`. Discover the full surface with `disrobe --help`, drill into any subcommand with `disrobe <pass> --help`, list passes with `disrobe passes`, and list installable optional tools with `disrobe install --list`.

## The five-rung IR ladder

Every artifact climbs the same intermediate-representation ladder, which is what lets passes from completely different ecosystems compose through a shared `.dr` envelope:

```text
   Raw  -->  Disasm  -->  MIR  -->  HIR  -->  Surface
   bytes     opcodes      mid       high      source
```

Unpacking and decryption passes operate at **Raw** (byte-identical unpack lives here). Disassembly produces **Disasm**. Decompilers do their structural work at **MIR** (for Python, the frame-tree pre-pass reconstructs nested constructs from the 3.11+ exception table before the instruction walk) and **HIR**, then render **Surface** - where Python output is recompiled and verified opcode-for-opcode. See the [architecture docs](https://1-3-7.github.io/disrobe/architecture.html) for the full model.

## Common flags

| Flag | Effect |
|---|---|
| `--json` / `--ndjson` / `--sarif` | Structured output (SARIF 2.1.0 for GitHub code scanning) |
| `--llm` | Emit the structured metadata sidecar (18 categories, 4 packs) for LLM consumers |
| `--dry-run` | Report what would happen, write nothing |
| `--no-cache` | Bypass the `.dr` envelope cache (output is identical either way) |
| `--seed <N>` | RNG seed for any non-deterministic backend |
| `--i-have-authorization` | Gate flag for grey-zone commercial protectors and the decryption-keys metadata |

## Safety posture

By default `disrobe` **does not execute the sample** - every default path is pure static analysis. The pickle suite is symbolic and never unpickles. The only code-execution paths (PyArmor v6/v7 dynamic-hook, BCC native lift) are behind explicit `--allow-dynamic` / `--allow-bcc` flags with a watchdog; run those inside a sandbox. The parsing surface is hardened. See [Forensics and malware-safety posture](https://1-3-7.github.io/disrobe/forensics-safety.html) and the full [threat-model](https://1-3-7.github.io/disrobe/threat-model.html).

## Documentation

The full docs site lives at **[1-3-7.github.io/disrobe](https://1-3-7.github.io/disrobe/)** - architecture, the IR ladder, the chain runner, per-language guides, the complete CLI reference, and the safety posture. The book source is under [`docs/`](docs/).

## Legal

Decompilation for security research, interoperability, and recovery of your own source is permitted in most jurisdictions (US DMCA Sec. 1201(f), EU Software Directive 2009/24/EC art. 6, UK CDPA Sec. 50B/50BA, and equivalents in CA/AU/JP). The full posture with statutory citations and a takedown channel is in [LEGAL.md](LEGAL.md).

> [!IMPORTANT]
> Grey-zone commercial protectors are gated behind the explicit `--i-have-authorization` flag and never run otherwise. Use is your responsibility per the statutory framing above.

## Contributing

Contributions welcome under the [Contributor Covenant 2.1](.github/CONTRIBUTING.md). For security issues, please open a [private advisory](https://github.com/1-3-7/disrobe/security/advisories/new) rather than a public issue. See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE-APACHE](LICENSE-APACHE) and [NOTICE](NOTICE).
