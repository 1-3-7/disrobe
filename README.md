# `disrobe`

[![CI](https://github.com/1-3-7/disrobe/actions/workflows/ci.yml/badge.svg)](https://github.com/1-3-7/disrobe/actions/workflows/ci.yml)
[![Docs](https://github.com/1-3-7/disrobe/actions/workflows/docs.yml/badge.svg)](https://1-3-7.github.io/disrobe/)
[![Release](https://img.shields.io/github/v/release/1-3-7/disrobe?sort=semver)](https://github.com/1-3-7/disrobe/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE-APACHE)
[![Rust 1.95+](https://img.shields.io/badge/rust-1.95%2B-orange.svg)](https://www.rust-lang.org)

**Strip the obfuscation, read the source. A deterministic, multi-language deobfuscator and decompiler in a single Rust binary - no model in the decompile path, output you can diff and cite.**

One tool peels the bytecode, packers, freezers, and protectors stacked across the modern software supply chain: Python (support range 1.0-3.15), JavaScript/TypeScript, WebAssembly, JVM + Android, .NET + native AOT, native PE/ELF/Mach-O, React Native Hermes, Flutter Dart AOT, Go, Lua/LuaJIT/Luau, PHP, Ruby, Erlang/Elixir (BEAM), Swift/Objective-C, AS3/Flash, Nim/Zig/Crystal, Perl/R/Tcl/Haxe, and the native packers commonly layered on top - in-house Python and JVM/Dalvik decompilers, PyArmor unpacker, PyInstaller/Nuitka extractor, dex-to-Java, UPX/kkrunchy/NSPack unpackers, JS unbundler, and a WASM lifter, all in one place.

Full documentation: **[1-3-7.github.io/disrobe](https://1-3-7.github.io/disrobe/)**

```sh
$ disrobe auto suspect.exe --out recovered/
# detected: PE -> UPX -> rust-demangle
# stage 01-upx        ok    (byte-identical unpack, 1.18 MiB in 9 ms)
# stage 02-demangle   ok    (Rust + C++ symbols demangled, 0 unresolved)
# final               ok    -> recovered/final/
```

## What `disrobe` is

`disrobe` removes the obfuscation, freezing, packing, and protection layers off a binary so you can read what it actually does - without executing it. It is built for forensic and recovery work where reproducibility matters:

- **Deterministic.** No model anywhere in the decompile path. Same input, same output, every machine, every run - so the output is a usable evidence and diff baseline.
- **In-house decompilers by default.** The Python, JVM/Kotlin, Dalvik, .NET CIL, and WASM decompilers are written in Rust and are the product. External decompilers (CFR, Vineflower, Procyon, jadx, ILSpy, dnSpy, de4dot) are optional `--backend` fallbacks, never the default. For native PE/ELF/Mach-O, `disrobe` is the unpack and symbol-recovery layer that feeds Ghidra/IDA/Binary Ninja cleaner input - it does not compete with them on raw decompilation.
- **Single static binary.** No JVM, no Python runtime, no Docker. One `cargo build --release`. Drops into CI headlessly.
- **Content-addressed.** Every artifact persists as a `.dr` envelope (rkyv hot payload + postcard cold sidecar + BLAKE3 root). Cache hits are byte-identical; chains compose offline.
- **Honest, gated, measured.** Every recovery is checked against an independent ground truth - recovered Python is recompiled on the matching interpreter and diffed opcode-for-opcode; unpacked bytes are compared to the original. Lossy recovery is labelled (`SEMANTIC` / `PARTIAL` / `SKELETON`) with a measured ledger and never rounded up. Commercial-tier protectors `disrobe` cannot fully unpack are reported as detect-only by design.
- **Agent-ready.** Any pass can emit a structured `--llm` metadata sidecar (call graph, types, control flow, capability surface, decompile provenance) so a coding agent reasons about recovered code without re-deriving it.

## Headline capability and honest numbers

Every number below is enforced by a test in `crates/*/tests/`; the ceiling ledger and the de-circularized oracle work are spelled out in [Ceilings and what is deferred](#ceilings-and-what-is-deferred).

- **Python decompiler - two honest metrics, not one rounded one:**
  - **Per-construct gate: 100%.** Every supported Python construct is compiled, decompiled, then recompiled on its own CPython interpreter and diffed for bytecode equivalence, across the full **3.6-3.15** stable matrix (10 versions x 100+ constructs, threshold pinned at 100%). Fully deterministic, in-house Rust, no model. Verified by `cargo test -p disrobe-pass-py-decompile --test construct_roundtrip`.
  - **Whole-corpus monolith: ~28.9% and climbing.** A single 2000-line kitchen-sink stress module must recompile to equivalent bytecode *in its entirety* - one diff anywhere fails the whole file. The honest measured frontier is **13/44 modules (~28.9%)**, ratcheted up per commit and never lowered (`WHOLE_MODULE_FLOOR_PCT`). This is the stress-test frontier, not a capability cap. Verified by `cargo test -p disrobe-pass-py-decompile --test roundtrip_metric`.
  - **`1.0-3.15` is a support range, not an accuracy claim.** The modern gate runs on-box interpreters (3.6+). Legacy 1.0-2.5 has no installable interpreter, so it is **token-match only** (recovered source compared to the original tokens, not recompiled); the 1.0-3.5 legacy band measures ~84% value-equivalent.
- **JVM and Android - in-house Rust decompilers as the default.** Java/Kotlin `.class` and Dalvik `.dex` lift through the same structurer. dex2jar produces **real method bodies at ~20.3% byte-exact** plus **100% of method signatures and control-flow structure**; body fidelity has an honest **~60-75% ceiling** because Dalvik erases local names, generics, and lambda desugaring. APK signature schemes v1/v2/v3 verify; RASP and dead-protector families are detect-only. Verified by `cargo test -p disrobe-pass-jvm` (`dex2jar_real_bodies`, `dalvik_decompile_oracle`, `apk_signature_verify`).
- **PyArmor - 70/72 real-corpus source recoveries** across v6 through v9-pro (default + super + no-wrap), measured on the committed real-wrapper corpus, not synthetic fixtures. Verified by `cargo test -p disrobe-pass-pyarmor --test static_unpack_corpus`.
- **Native packers - byte-honest, per-packer:** UPX byte-identical (clean-room NRV2B, ~0.01-0.03% diff = section padding/timestamps); **kkrunchy classic 100.00%** byte-exact via the in-house stub emulator (k7 variant 6.44%, a closed-source PAQ ceiling); **NSPack 98.59-99.34%** content-section recovery; **Petite ~97.8%** content (x86 stub emulation); **MPRESS ~91.6-92.4%**; FSG 2/3 byte-identical; MEW/M020/ASPack/PECompact/Yoda's covered. VMProtect/Themida are detect + section-carve (full devirtualization is explicitly deferred). Per-fixture scores live in `corpus/native/packers/MANIFEST.toml`.

## De-circularized oracles

A self-referential test - decompile something this tool obfuscated, then "verify" against the same tool's notion of correct - inflates coverage to nothing. This sprint each of the following oracles was rebuilt to gate on an **independent** ground truth (a real third-party tool's output, a real binary's own symbol table, or an in-band CPython recompile), with an anti-gaming playground that plants a circular canary and asserts the real tree trips zero circular findings:

- **Python decompile** - in-band CPython recompile-equivalence (the interpreter is the judge, not `disrobe`).
- **PyArmor** - real `_pytransform` ELF/Mach-O wrappers, synthetic-tautology oracle deleted.
- **py-deob** - **12/14 obfuscator families** recovered on a corpus generated by the real third-party obfuscation tools (2 families are sourcing-blocked, marked, not faked).
- **js-deob** - differential against the real obfuscator output, plus reconstructed webpack source maps.
- **PyInstaller** - committed non-circular carchive round-trip.
- **Nim/Zig/Crystal** - symbols and metadata recovered from each binary's *own* symtab and type table; `source_recoverable=false` is asserted (these are compiled languages - demangling and symbol recovery is the real deliverable, not source).

## Supported languages and formats

Every cell is backed by a fixture in `corpus/` and an integration test in `crates/*/tests/` - nothing is aspirational.

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
| **Native packers** | UPX (byte-identical), kkrunchy classic (byte-exact), NSPack, Petite, MPRESS, FSG, MEW, ASPack, PECompact, Yoda's via clean-room decoders + an in-house x86 stub emulator. Honest detect + carve on the virtualized tier (VMProtect, Themida, Enigma, ...). |
| **Go** | GoReSym + redress symbol recovery, garble undo, embedded-FS walker, pclntab 1.2-1.26 (557/557 type-name resolution on 1.26.3, locally reproducible). |
| **Nim / Zig / Crystal** | Detect + name-demangle + symbol/metadata recovery from each binary's own symtab and type table. Source is not recoverable (compiled languages); demangling is the deliverable. |
| **Perl / R / Tcl / Haxe** | Tcl starkit byte-identical extract, R `.rds` round-trip, Perl `B::Concise` op-tree, Haxe cross-target detect + route. |
| **Lua** | 5.1-5.4, LuaJIT 2.0/2.1, Luau, GLua, and 11 obfuscators including MoonSec v1-v3 and Ironbrew2. |
| **Shell** | PowerShell Invoke-Obfuscation levels 1-6, Bashfuscator, batch, VBA p-code (detect-only header parse). |
| **PHP / Ruby / BEAM** | ionCube/SourceGuardian/Zend Guard structural decode + Phar; MRI/YARV 1.9-3.4 + mruby decompile; BEAM chunk parse + Core Erlang lift + Elixir `Dbgi`. |
| **React Native Hermes** | Bytecode v60-v96, validated locally on a non-redistributable 66 MiB Discord bundle: 122,633 functions, 0 errors. |
| **Flutter / Swift / AS3** | Dart AOT snapshot parser; Mach-O class-dump + SwiftConfidential/SwiftShield rename-undo; SWF + ABC bytecode disasm (local corpus only; not CI-validated). |
| **Python pickle** | Static disasm + symbolic-VM trace + safety grading + polyglot + ML-model detection. Never unpickles. |
| **Containers** | 26 formats (ZIP/tar/7z/`.deb`/`.rpm`/`.iso`/MSI/NSIS/Docker/OCI/SquashFS/...) with auto-detect, chaining, and universal zip-slip + bomb guards. |

## Comparison

`disrobe`'s structural angle against the field: a single static binary, deterministic (no LLM in the decompile path), content-addressed output, and round-trip verification - across every ecosystem below, not one.

| Ecosystem | Leading tools | Where `disrobe` differs |
|---|---|---|
| **Python** | pycdc, pylingual, uncompyle6, decompyle3, pychd | Spans 3.6-3.15 in one engine with in-band recompile-equivalence; fully deterministic, no LLM, no benchmark-contamination. uncompyle6 stops at 3.8, decompyle3 ~3.9; the ML-based tools are non-reproducible and contamination-flagged. |
| **JVM / Android** | CFR, Vineflower, Procyon, jadx | In-house Rust decompiler is the default (those become optional `--backend`s); adds chain auto-detect, `.dr` envelopes, and APK sig verify in one binary. |
| **.NET / CIL** | ILSpy, dnSpy, de4dot | In-house CIL to C#/F#/VB plus a modern obfuscator-reverser fork; de4dot froze in 2020. Deterministic `.dr` output. |
| **Native** | Ghidra, IDA, Binary Ninja | `disrobe` does not compete on raw decompilation - it is the unpack + symbol-recovery + chain-detect layer that feeds them cleaner input. |
| **Native packers** | per-packer one-off scripts; UPX only unpacks UPX | First general-purpose FOSS unpacker for the tier, with an in-house x86 stub emulator and per-fixture honest byte-recovery scores. |
| **JS** | webcrack, synchrony, REstringer | Full obfuscator.io + JS-Confuser + Jscrambler + 10 bundlers with source-map reconstruction, behind a deterministic codegen. |
| **WASM** | wasm-decompile, wasm2c, wasm-tools | The only one lifting to typed Rust/TS/WAT/C with DWARF recovery and obfuscator reversers. |

Full per-ecosystem comparison tables (freezers, protectors, Lua, shell, PHP, Ruby, BEAM, Swift, Flash, Hermes, Flutter, containers) are in the [docs](https://1-3-7.github.io/disrobe/).

## Ceilings and what is deferred

`disrobe` states its limits in the open. None of these is rounded up or hidden.

- **Lossy bytecode-to-source.** `.class` / `.dex` / CIL erase local names, generics, comments, and exact formatting; recovery is structurally faithful but never byte-identical (Dalvik body ceiling ~60-75%).
- **Nuitka native bodies.** Onefile/standalone unpack is byte-exact, but Nuitka compiles Python to C to native, so recovered function bodies are skeleton-to-partial (~30-50%); symbols and constants recover cleanly.
- **Compiled languages (Nim / Zig / Crystal).** No source recovery is possible; demangling, symbol, and metadata recovery from the binary's own tables is the real deliverable.
- **Virtualized packers.** VMProtect / Themida / Enigma and the commercial tier are detect + section-carve only; full devirtualization is explicitly deferred to a dedicated VM-lifter pass. ASProtect / Morphine are detect + scaffold (byte-unpack is sourcing-blocked).
- **kkrunchy k7** is capped at 6.44% by its closed-source PAQ backend; the classic variant is byte-exact 100%.
- **Sourcing-blocked** (no obtainable real sample, never faked): Bangcle / Ijiami / Qihoo Android packers, DexGuard control-flow obfuscation, the Minecraft-modding obfuscator family, PyArmor v9 HWID/license/network bind-mode, and assorted mobile artifacts.
- **Distribution** is GitHub Releases + prebuilt binaries + the mdBook Pages site only - no PyPI/npm/Homebrew/AUR/Scoop/winget/Docker/crates.io.

## Install

Prebuilt binaries from the Releases tab, or build from source.

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
disrobe jvm decompile app.apk --out src/             # in-house Dalvik decompiler is the default
disrobe dotnet decompile App.dll --out src/          # in-house CIL decompiler is the default
disrobe native unpack packed.exe --out unpacked.bin
disrobe go recover app --out symbols.json
disrobe lua decompile script.luac --out script.lua
disrobe hermes lift index.android.bundle --out surface/
```

`disrobe auto` fingerprints the input and chains the full pipeline in one call (`PE -> UPX -> rust-demangle`, `APK -> dex -> Java`, `PyInstaller -> PyArmor -> .pyc decompile`); with `--capture-stages`, stage outputs land in `out/01-*/`, `out/02-*/`, ..., `out/final/`. Discover the full surface with `disrobe --help`, drill into any subcommand with `disrobe <pass> --help`, list passes with `disrobe passes`, and list optional external tools with `disrobe install --list`.

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
| `--backend <tool>` | Select an optional external decompiler instead of the in-house default |
| `--dry-run` | Report what would happen, write nothing |
| `--no-cache` | Bypass the `.dr` envelope cache (output is identical either way) |
| `--seed <N>` | RNG seed for any non-deterministic backend |
| `--i-have-authorization` | Gate flag for grey-zone commercial protectors and the decryption-keys metadata |

## Safety posture

By default `disrobe` **does not execute the sample** - every default path is pure static analysis. The pickle suite is symbolic and never unpickles. The only code-execution paths (PyArmor v6/v7 dynamic-hook, BCC native lift) are behind explicit `--allow-dynamic` / `--allow-bcc` flags with a watchdog; run those inside a sandbox. The parsing surface is hardened. See [Forensics and malware-safety posture](https://1-3-7.github.io/disrobe/forensics-safety.html) and the full [threat model](https://1-3-7.github.io/disrobe/threat-model.html).

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
