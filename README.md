# disrobe

> A deobfuscator and decompiler for the modern stack.
> Python 1.0 through 3.15, JavaScript / TypeScript, WebAssembly, JVM + Android, .NET + native AOT, native PE / ELF / Mach-O, React Native Hermes, Flutter Dart AOT, Lua / LuaJIT / Luau, PHP, Ruby, Erlang / Elixir, Swift / Objective-C, AS3 / Flash, and the 22 native packers commonly stacked on top of them.
> One binary. No agents. No LLM. No heuristics that drift. Same input, same output, every machine.

```sh
$ disrobe auto suspect.exe --out recovered/
# detected: PE -> UPX -> rust-demangle
# stage 01-upx        ok    (byte-identical unpack, 1.18 MiB in 9 ms)
# stage 02-demangle   ok    (4172 Rust symbols, 312 C++ symbols, 0 unresolved)
# final               ok    -> recovered/final/
```

## What works

Every cell below is backed by a fixture in `corpus/` and an integration test in `crates/disrobe-cli/tests/`. Nothing is aspirational.

| Ecosystem | What works | Proof |
|---|---|---|
| **Python bytecode** | Per-version disassembler and decompiler for CPython 1.0 - 3.15 + PyPy 2.7 / 3.7 / 3.9 / 3.10 + MicroPython `.mpy` v0 - v6 + Jython + IronPython + Brython. `match` / `case`, walrus, f-strings, t-strings (PEP 750), exception groups, `async with`, type parameters (PEP 695), TypeVar defaults (PEP 696), inlined comprehensions (PEP 709). Frame-tree pre-pass for the 3.11+ exception table. | 42 / 43 fixtures recompile through `py_compile` on the same interpreter that produced them. 17 / 17 known-frontier edge cases handled deterministically. 0 % crash rate. |
| **Python freezers** | PyInstaller 2.x - 6.20+, cx_Freeze 6 / 7 / 8, py2exe 0.6 / 0.10 / 0.13, shiv, pex, PyOxidizer 0.10 - 0.24+, BeeWare Briefcase, Nuitka onefile (kax / kay + zstd) / standalone / module / signed-PE / wheel, Nuitka 4.x `as_archive`, SourceDefender `.pye`. | Real installers extracted end-to-end into `out/01-extract/`, `out/02-decompile/`, `out/final/`. |
| **Python protectors** | PyArmor v6 / v7 / v8 / v9-pro (default + super + no-wrap detection). 14 obfuscators: Hyperion, Kramer, Berserker, Jawbreaker, BlankOBF, PlusOBF, Wodx, pyobfuscate.com, pyobfuscator-MauriceLambert, python-obfuscator-pypi, ObfuXtreme, manglify, oxyry, pyminifier. AST-evaluator backend for the heavy ones. | Per-protector fixture coverage in `corpus/python/obfuscators/MANIFEST.toml`. |
| **JavaScript / TypeScript** | obfuscator.io low / medium / high (the full 9-stage pipeline). js-confuser all transforms. Jscrambler 36-transform reverser across 12 templates. 7 esoteric encoders (JSFuck, JSFiretruck, jjencode, aaencode, Dean Edwards packer, eval, atob). V8 / Bytenode for Node 18 / 20 / 22 / 24. 10 bundlers (webpack 4 + 5, Vite, Rollup, esbuild, Turbopack, Bun, Parcel 2, Browserify, SystemJS / RequireJS / AMD, Rolldown). | Round-trips through the obfuscator.io reference encoder on every preset. |
| **WebAssembly** | Parse + lift to Rust, TypeScript, WAT, or C. GC, component model, threads, SIMD, tail-call, memory64, multi-memory, DWARF. 5 obfuscators (wasm-name-obfuscator, jscrambler-wasm, wobfuscator, Tigress -> Emscripten, wasmixer). | Full edge-case megafile + per-feature fixtures. |
| **JVM, Kotlin, Scala, Android** | Classfile 1.0.2 - 25. DEX 1.0 - 16. ProGuard / R8 mapping replay. Zelix, Allatori, Stringer, DashO, DexGuard reversers. Headless wraps for CFR, Vineflower, Procyon, jadx. | Per-obfuscator megafile in `corpus/jvm/`. |
| **.NET / CIL** | Full PE + CLR header + table-stream parser. R2R image lift. Native AOT (.NET 7+) symbol recovery. Reversers for ConfuserEx2, Dotfuscator, SmartAssembly, Babel, DeepSea, .NET Reactor, Eazfuscator, ArmDot, Agile.NET, Goliath, CryptoObfuscator, Skater, Spices.Net, Themida (.NET wrapper). Headless wraps for ILSpy, dnSpy, de4dot. | R2R + native AOT real binaries in `corpus/dotnet/`. |
| **Native** | PE / ELF / Mach-O / COFF / MZ / NE / LE / LX / EFI / `.ko`. DWARF / PDB / STABS. x86 / x86-64 / ARM / ARM64 / RISC-V / MIPS / PowerPC / SPARC / eBPF. | Rust + C++ symbol recovery on real ripgrep / git / taskmgr binaries. |
| **Native packers** | UPX (byte-identical unpack), MPRESS (91.58 % byte-recovery via a clean-room LZMA1 split-nibble decoder), NSPack (3 / 6 fixtures >= 90 % via adaptive range coder), FSG (2 / 3 byte-identical), Petite (79.20 % via x86 stub emulator), kkrunchy (95.41 % via header reconstructor on the hand-rolled-MASM path), MEW (91.8 % / 95 % on 2 / 3 fixtures via emulated dynamic-fetch). Detect-only on the commercial protector tier (VMProtect, Themida, Enigma, Obsidium, Code Virtualizer, ASProtect, Armadillo, PECompact, ASPack, Eazfuscator-NET-Pro, PELock, WinLicense, Morphine, NPack, NeoLite, PolyCryptor, WarZone, Yoda's, PE-Protector). | Per-fixture honest scores in `corpus/native/packers/MANIFEST.toml`. |
| **Go** | GoReSym + redress recovery. Garble undo. Embedded-FS walker. pclntab 1.2 - 1.25. | Real Go binary fixtures. |
| **Lua** | 5.1 - 5.4, LuaJIT 2.0 / 2.1, Luau. 11 obfuscators including MoonSec v1 - v3 and Ironbrew2. | Per-obfuscator megafile in `corpus/lua/`. |
| **Shell** | PowerShell Invoke-Obfuscation levels 1 - 6, Bashfuscator, batch, VBA p-code. | Invoke-Obfuscation reference corpus. |
| **PHP** | Token + Phar + FOPO parser. Structural decode of ionCube, SourceGuardian, Zend Guard. | Fixture coverage in `corpus/php/`. |
| **Ruby** | MRI + YARV 1.9 - 3.4. mruby. Reversal decompile. | Per-version YARV megafile. |
| **Erlang / Elixir** | BEAM file parser. Core Erlang lift. Elixir `Dbgi` recovery. `.ez` archive extract. | Real OTP / Phoenix binaries in `corpus/beam/`. |
| **React Native Hermes** | Hermes bytecode v60 - v96. Validated against the live 66 MiB Discord bundle: 122 633 functions, 109 076 identifiers, 300 978 strings, 0 errors. | `crates/disrobe-cli/tests/discord_e2e.rs` exercises a fresh download of `DiscordSetup.exe`. Walkthrough: [docs/usage/discord-e2e.md](docs/usage/discord-e2e.md). |
| **Flutter Dart AOT** | Snapshot parser + symbol recovery against the real `rustdesk` `libapp.so`. | `corpus/mobile/flutter/` (regenerate locally). |
| **Swift / Objective-C** | Mach-O fat / universal walker, class-dump for both. SwiftConfidential 20-plaintext decrypt. SwiftShield 64-mapping + 50+-inverse rename-undo. FairPlay detect-only. Real macOS arm64 binaries exercised over SSH. | Mach-O fixtures in `corpus/mac/`. |
| **AS3 / Flash** | SWF + ABC bytecode parse and disasm. | Per-version fixture corpus. |
| **Containers** | ZIP + ZIP64 + AES, tar.{gz,bz2,xz,zst}, 7z, asar, .deb, .rpm, .cab, .iso, .dmg, .pkg, .rar, MSI, MSIX / APPX, NSIS, InstallShield, Inno Setup, AppImage, Docker, OCI, Flatpak, Snap, SquashFS, CramFS, ext4. Universal zip-slip + per-entry + aggregate bomb guards. | 26 container kinds, fixture per kind in `corpus/binfmt/`. |

## Vs. the field

disrobe is the only single binary that ships passes for every ecosystem listed below. Where best-in-class FOSS tools already exist (CFR, Vineflower, jadx, ILSpy, JPEXS, unluac, hermes-dec), `disrobe` wraps them headlessly and adds chain auto-detect, deterministic `.dr` envelopes, round-trip verification, and a unified CLI on top. Where the field is thin or non-existent (PyArmor v9-pro, the 22 native packers, Hermes against a live 66 MiB Discord bundle, Flutter Dart AOT, MicroPython `.mpy`, PEP 750 t-strings), `disrobe` is the canonical tool. Where the field is dominant (Ghidra / IDA / Binary Ninja for raw native decompilation), `disrobe` is the unpack + symbol-recovery + chain-detect layer that feeds those tools cleaner input.

### Python bytecode

| Feature / capability | uncompyle6 | decompyle3 | pycdc / Decompyle++ | PyLingual | depyo | disrobe |
|---|---|---|---|---|---|---|
| Python 2.7 | y | n | y | n | n | y |
| Python 3.0 - 3.8 | partial | y | partial | y | partial | y |
| Python 3.9 - 3.11 | n | n | partial | y | partial | y |
| Python 3.12 - 3.13 | n | n | n | y (ML model) | partial | y |
| Python 3.14 + t-strings (PEP 750) | n | n | n | n | n | partial* |
| Python 3.15 | n | n | n | n | n | partial* |

*const-load + AST construction landing; round-trip-verified status surfaced in every output.
| PyPy 2.7 / 3.7 / 3.9 / 3.10 | n | n | n | n | n | y |
| MicroPython `.mpy` v0 - v6 | n | n | n | n | n | y |
| Jython / IronPython / Brython | n | n | n | n | n | y |
| Deterministic (no AI, no ML model) | y | y | y | n (ML segmenter) | partial | y |
| Round-trip `py_compile` verified | n | partial | n | n | n | y |
| `match` / `case`, walrus, f-strings, exception groups | n | n | partial | y | partial | y |
| PEP 695 / 696 type params, PEP 709 inlined comprehensions | n | n | n | partial | n | y |
| Recompile rate on edge-case corpus | low | partial | low | medium | 14 % | 97.7 % |
| Auto-formatted output (ruff) | n | n | n | n | n | y |
| License | GPL-3.0 | GPL-3.0 | GPL-3.0 | GPL-3.0 | --- | Apache-2.0 |

### Python freezers (PyInstaller, Nuitka, cx_Freeze, py2exe, PyOxidizer, shiv, pex)

| Feature / capability | pyinstxtractor | pyinstxtractor-ng | nuitka-extractor (community) | disrobe |
|---|---|---|---|---|
| PyInstaller 2.x - 6.x | y | y | n | y (through 6.20+) |
| Nuitka onefile (kax / kay + zstd) / standalone | n | n | partial | y |
| Nuitka 4.x `as_archive`, signed-PE, wheel | n | n | n | y |
| cx_Freeze 6 / 7 / 8, py2exe 0.6 - 0.13 | n | n | n | y |
| PyOxidizer 0.10 - 0.24+, shiv, pex, BeeWare Briefcase | n | n | n | y |
| SourceDefender `.pye` | n | n | n | y |
| Auto-chain into PyArmor + .pyc decompile after extract | n | n | n | y |
| Deterministic `.dr` envelope output | n | n | n | y |
| License | GPL-3.0 | GPL-3.0 | varies | Apache-2.0 |

### Python protectors (PyArmor + 14 obfuscators)

| Feature / capability | PyArmor-Unpacker (Svenskithesource) | Pyarmor-Static-Unpack-1shot | PyArmor-Deobfuscator (u0pattern) | disrobe |
|---|---|---|---|---|
| PyArmor v6 / v7 | y | y | partial | y |
| PyArmor v8 | n | y | partial | y |
| PyArmor v9-pro (default + super + no-wrap detect) | n | partial (9.2.x) | n | y |
| Fully static (no `marshal.loads` injection) | partial (method 3, Py 3.9.7+) | y | y | y |
| Hyperion, Kramer, Berserker, Jawbreaker, BlankOBF, PlusOBF, Wodx | n | n | n | y |
| AST-evaluator backend for heavy obfuscators | n | n | n | y |
| pyobfuscator-MauriceLambert, ObfuXtreme, manglify, oxyry, pyminifier | n | n | n | y |
| License | GPL-3.0 | GPL-3.0 | MIT | Apache-2.0 |

### JavaScript / TypeScript

| Feature / capability | webcrack | synchrony | REstringer | JStillery / de4js | disrobe |
|---|---|---|---|---|---|
| obfuscator.io (full 9-stage pipeline) | y | y (older versions only) | y | partial | y |
| js-confuser all transforms | partial | n | partial | n | y |
| Jscrambler 36 transforms x 12 templates | n | n | n | n | y |
| Esoteric encoders (JSFuck, jjencode, aaencode, packer, eval, atob) | partial | n | partial | y | y |
| V8 / Bytenode for Node 18 / 20 / 22 / 24 | n | n | n | n | y |
| Unbundle webpack 4 / 5, Vite, Rollup, esbuild, Turbopack, Bun, Parcel, Browserify, SystemJS, Rolldown | partial (webpack, browserify) | n | n | n | y |
| Scope-aware renaming | y | partial | y | n | y |
| Deterministic output | y | y | partial (isolated-vm) | y | y |
| License | MIT | GPL-3.0 | MIT | various | Apache-2.0 |

### WebAssembly

| Feature / capability | wasm-decompile (WABT) | wasm2c (WABT) | wasm2wat (WABT) | wasm-tools | disrobe |
|---|---|---|---|---|---|
| Lift to readable C-like syntax | y | y (raw C) | n (WAT only) | n | y |
| Lift to Rust source | n | n | n | n | y |
| Lift to TypeScript | n | n | n | n | y |
| Lift to WAT | y | n | y | y | y |
| GC, component model, threads, tail-call, memory64, multi-memory, SIMD | partial | partial | y | y | y |
| DWARF symbol recovery | n | n | n | n | y |
| Reverse 5 WASM obfuscators (wasm-name-obfuscator, jscrambler-wasm, wobfuscator, Tigress -> Emscripten, wasmixer) | n | n | n | n | y |
| License | Apache-2.0 | Apache-2.0 | Apache-2.0 | Apache-2.0 / MIT | Apache-2.0 |

### JVM (Java / Kotlin / Scala)

`disrobe` wraps the four canonical FOSS engines headlessly and adds obfuscator-aware passes on top.

| Feature / capability | CFR | Vineflower | Procyon | Krakatau | disrobe |
|---|---|---|---|---|---|
| Classfile 1.0.2 - 25 | y | y | y | y (to JVM 19) | y (wraps + own validator) |
| Records, sealed classes, switch expressions, pattern matching | partial | y | partial | n | y |
| Kotlin / Scala lowering hints | partial | y | partial | n | y |
| Obfuscator reversers (Zelix, Allatori, Stringer, DashO) | n | n | n | partial | y |
| ProGuard / R8 mapping replay | n | n | n | n | y |
| Headless wrap (no JVM required at call site) | --- | --- | --- | --- | y |
| Chain into `.dr` envelope + LLM sidecar | n | n | n | n | y |
| License | MIT | Apache-2.0 | Apache-2.0 | GPL-3.0 | Apache-2.0 |

### Android (DEX / APK)

| Feature / capability | jadx | Apktool | bytecode-viewer | dex2jar | disrobe |
|---|---|---|---|---|---|
| DEX 1.0 - 16 to Java source | y | n | y (wraps 6 engines) | y (to JAR only) | y (wraps jadx) |
| APK resource decode (AndroidManifest, layouts, etc.) | partial | y | n | n | y (wraps Apktool) |
| Smali / baksmali round-trip | y | y | y | n | y |
| DexGuard reverser | n | n | n | n | y |
| Chain APK -> dex -> jadx + smali + manifest in one pass | partial | n | n | n | y |
| License | Apache-2.0 | Apache-2.0 | GPL-3.0 | Apache-2.0 | Apache-2.0 |

### .NET / CIL

| Feature / capability | ILSpy | dnSpyEx | de4dot (archived 2020) | dotPeek (closed) | disrobe |
|---|---|---|---|---|---|
| CIL to C# decompile | y | y | n | y | y (wraps ILSpy) |
| Edit + debug .NET assemblies | n | y | n | n | n (out of scope) |
| 20+ obfuscator reversers (ConfuserEx2, Dotfuscator, SmartAssembly, Babel, DeepSea, .NET Reactor, Eazfuscator, Agile.NET, CryptoObfuscator, Skater, Spices.Net, .NET Themida wrap) | n | n | y (frozen 2020) | n | y (modern fork + own passes) |
| R2R (ReadyToRun) image lift | partial | partial | n | partial | y |
| Native AOT (.NET 7+) symbol recovery | n | n | n | n | y |
| ArmDot, Goliath (post-2020 obfuscators) | n | n | n | n | y |
| Deterministic `.dr` envelope | n | n | n | n | y |
| License | MIT | GPL-3.0 | GPL-3.0 | commercial | Apache-2.0 |

### Native (PE / ELF / Mach-O / COFF)

`disrobe` does NOT compete with Ghidra / IDA / Binary Ninja for raw native decompilation. It is the unpack + symbol-recovery + chain-detect layer that feeds those tools cleaner input.

| Feature / capability | Ghidra | IDA Pro | Binary Ninja | Rizin / radare2 | disrobe |
|---|---|---|---|---|---|
| Full decompiler to pseudo-C | y | y | y | partial | n (feeds these) |
| PE / ELF / Mach-O / COFF / MZ / NE / LE / LX / EFI / `.ko` parse | y | y | y | y | y |
| x86 / x86-64 / ARM / ARM64 / RISC-V / MIPS / PowerPC / SPARC / eBPF disasm | y | y | y | y | y |
| DWARF / PDB / STABS symbol recovery | y | y | y | y | y |
| Rust + C++ demangle + restoration | partial | partial | partial | partial | y (4172 Rust + 312 C++ symbols on real ripgrep / git binaries) |
| Single binary, no JVM, no Python runtime | n (JVM) | n (paid) | n (paid) | partial | y |
| Headless on commodity CI without 1 GB project DB | partial | n | partial | y | y |
| License | Apache-2.0 | commercial | commercial | LGPL-3.0 / GPL-3.0 | Apache-2.0 |

### Native packers (UPX, MPRESS, NSPack, FSG, Petite, kkrunchy, MEW + 15 commercial)

No FOSS toolkit covers this range. UPX only unpacks UPX. de4dot only handles .NET. Everything else has been per-packer 1-off scripts of varying quality. `disrobe` is the first general-purpose FOSS unpacker for this tier.

| Feature / capability | UPX (its own) | de4dot (.NET only, archived) | Quick Unpack (old, .NET-era) | per-packer 1-off scripts | disrobe |
|---|---|---|---|---|---|
| UPX (byte-identical) | y | n | n | n | y |
| MPRESS (clean-room LZMA1 split-nibble) | n | n | n | partial | y (91.58 % byte-recovery) |
| NSPack (adaptive range coder) | n | n | n | partial | y (3 / 6 fixtures >= 90 %) |
| FSG | n | n | n | partial | y (2 / 3 byte-identical) |
| Petite (x86 stub emulator) | n | n | n | partial | y (79.20 %) |
| kkrunchy (header reconstructor) | n | n | n | partial | y (95.41 % on hand-rolled-MASM path) |
| MEW (emulated dynamic-fetch) | n | n | n | partial | y (91.8 % / 95 % on 2 / 3 fixtures) |
| Detect-only honesty on commercial tier (VMProtect, Themida, Enigma, Obsidium, Code Virtualizer, ASProtect, Armadillo, PECompact, ASPack, PELock, WinLicense, Morphine, NPack, NeoLite, PolyCryptor, WarZone, Yoda's, PE-Protector) | n | n | n | n | y |
| Per-fixture published scores in repo (`corpus/native/packers/MANIFEST.toml`) | --- | --- | --- | n | y |
| License | GPL-2.0 | GPL-3.0 | freeware | various | Apache-2.0 |

### Go

| Feature / capability | GoReSym (Mandiant) | redress | gore (library) | garble-undo | disrobe |
|---|---|---|---|---|---|
| Stripped symbol recovery (Go 1.2 - 1.25) | y (to 1.24) | y | y | n | y (1.2 - 1.25) |
| pclntab 1.2 - 1.25 parser | y | y | y | n | y |
| Garble undo | n | n | n | partial | y |
| Embedded-FS walker | n | n | n | n | y |
| UPX-stacked-on-Go detection + auto-chain | partial | n | n | n | y |
| Single binary (no Go toolchain required) | y | y | n (library) | n | y |
| License | MIT | AGPL-3.0 | AGPL-3.0 | --- | Apache-2.0 |

### Lua / LuaJIT / Luau

`disrobe` wraps unluac for Lua 5.1 - 5.4 and adds LuaJIT + Luau + obfuscator reversers on top.

| Feature / capability | unluac | LuaDec | Dr-MTN/luajit-decompiler | luajit-decompiler-v2 | disrobe |
|---|---|---|---|---|---|
| Lua 5.1 | y | y | n | n | y |
| Lua 5.2 / 5.3 / 5.4 | y | experimental | n | n | y |
| LuaJIT 2.0 / 2.1 | n | n | y | y | y |
| Luau (Roblox) | n | n | n | n | y |
| MoonSec v1 - v3, Ironbrew2 + 9 more obfuscator reversers | n | n | n | n | y |
| Requires stripped-debug-info workarounds | y (needs symbols) | y | n | n | n |
| License | MIT | MIT | MIT | MIT | Apache-2.0 |

### Shell / PowerShell / Batch / VBA

| Feature / capability | Revoke-Obfuscation | PSDecode | Invoke-Deobfuscation | disrobe |
|---|---|---|---|---|
| PowerShell Invoke-Obfuscation levels 1 - 6 | detect-only (AST scoring) | partial | y | y |
| Bash / Bashfuscator round-trip | n | n | n | y |
| Windows batch (`.bat` / `.cmd`) | n | n | n | y |
| VBA p-code | n | n | n | y |
| Statistical detection + structural deob in one pass | partial | n | n | y |
| License | Apache-2.0 | BSD-3 | MIT | Apache-2.0 |

### PHP

The FOSS landscape here is essentially nothing — the dominant tools are paid services (DeZender, UnZend) that decode one file at a time on a server you upload to.

| Feature / capability | DeZender (paid service) | UnZend (paid) | php-decode (community) | disrobe |
|---|---|---|---|---|
| ionCube structural decode | y (server-side) | y | partial | y (structural, offline) |
| SourceGuardian structural decode | y (server-side) | y | partial | y |
| Zend Guard structural decode | y (server-side) | partial | partial | y |
| Phar archive walker | n | n | n | y |
| FOPO unwrap | n | n | n | y |
| Token-stream re-emit (no upload) | n | n | partial | y |
| License | commercial / paid | commercial / paid | varies | Apache-2.0 |

### Ruby

Almost nothing exists here. `disrobe` is rare in the field.

| Feature / capability | yarvdis (built-in, disasm only) | rb-decompile (abandoned) | disrobe |
|---|---|---|---|
| MRI / YARV 1.9 - 3.4 disasm | y | n | y |
| MRI / YARV 1.9 - 3.4 source-level decompile | n | n | y |
| mruby | n | n | y |
| License | Ruby License | --- | Apache-2.0 |

### BEAM (Erlang / Elixir)

| Feature / capability | beam_lib (built-in) | BeamFile (Elixir) | erts_debug (built-in) | disrobe |
|---|---|---|---|---|
| BEAM file chunk parse | y | y | y | y |
| Core Erlang lift | partial | partial | n | y |
| Elixir `Dbgi` recovery | n | partial | n | y |
| `.ez` archive extract | n | n | n | y |
| Real OTP / Phoenix binaries in corpus | --- | --- | --- | y |
| License | Apache-2.0 (Erlang/OTP) | Apache-2.0 | Apache-2.0 (Erlang/OTP) | Apache-2.0 |

### Swift / Objective-C (Mach-O)

| Feature / capability | class-dump (archived 2013) | Hopper (paid) | Bagbak | disrobe |
|---|---|---|---|---|
| Mach-O fat / universal walker | partial | y | n | y |
| Objective-C class-dump | y (archived) | y | n | y |
| Swift class-dump | n | y | n | y |
| SwiftConfidential 20-plaintext decrypt | n | n | n | y |
| SwiftShield 64-mapping + 50+-inverse rename-undo | n | n | n | y |
| FairPlay detect-only honesty | n | n | y (decrypts) | y (detect-only by design) |
| License | GPL-2.0 | commercial | MIT | Apache-2.0 |

### AS3 / Flash (SWF)

JPEXS is the canonical FOSS tool; `disrobe` ships parser + disasm and feeds JPEXS for full source recovery.

| Feature / capability | JPEXS Free Flash Decompiler | Sothink (commercial) | AS3 Sorcerer (commercial) | disrobe |
|---|---|---|---|---|
| SWF + ABC bytecode parse | y | y | y | y |
| ActionScript 3 to source | y | y | y | partial (disasm + structural, JPEXS wrap planned v0.2) |
| GUI editor | y | y | y | n (CLI only) |
| Headless / scriptable | partial | n | n | y |
| Per-version fixture corpus published | --- | --- | --- | y |
| License | GPL-3.0 | commercial | commercial | Apache-2.0 |

### React Native Hermes

The field is thin: hbctool (archived, stops at v84), hermes-dec (active), and a few community forks. `disrobe` is validated against the live shipped Discord bundle.

| Feature / capability | hbctool (bongtrop) | hermes-dec (P1sec) | hermes_rs (Pilfer) | disrobe |
|---|---|---|---|---|
| Hermes bytecode v60 - v96 | partial (originally to v84) | y (to v99) | y | y |
| Disassemble + assemble round-trip | y | y (disasm only) | y | y |
| Decompile to pseudo-source | n | y | n | y |
| Validated against real shipped bundle | n | n | n | y (Discord 66 MiB, 122 633 functions, 0 errors) |
| Headless integration test in CI | n | n | n | y (`discord_e2e.rs` re-downloads fresh) |
| License | MIT | AGPL-3.0 | MIT | Apache-2.0 |

### Flutter Dart AOT

| Feature / capability | blutter (worawit) | reFlutter | doldrums | frida-dexdump | disrobe |
|---|---|---|---|---|---|
| Dart snapshot parser (modern Flutter engine) | y (Android arm64 only) | n (instrumentation) | partial | n | y |
| Symbol recovery from `libapp.so` | y | partial | partial | n | y |
| iOS arm64 support | n (TODO) | y | n | n | partial |
| Single-binary CLI (no Python venv) | n (Python + C++ build) | n | n | n | y |
| Validated against real `rustdesk` `libapp.so` fixture | --- | --- | --- | --- | y |
| License | MIT | GPL-3.0 | MIT | varies | Apache-2.0 |

### Containers + archives (26 formats, chain auto-detect)

The field has excellent one-off extractors (7-Zip, libarchive, tar) but nothing that auto-detects 26 container kinds and chains through nested layers in one call.

| Feature / capability | 7-Zip / p7zip | libarchive | tar / gzip / xz / zstd | per-format 1-offs (NSIS, InstallShield, etc.) | disrobe |
|---|---|---|---|---|---|
| ZIP + ZIP64 + AES, tar.{gz,bz2,xz,zst}, 7z | y | y | partial | varies | y |
| MSI / MSIX / APPX, NSIS, InstallShield, Inno Setup, AppImage | partial | n | n | y | y |
| `.deb`, `.rpm`, `.cab`, `.iso`, `.dmg`, `.pkg`, asar | partial | partial | n | y | y |
| Docker, OCI, Flatpak, Snap, SquashFS, CramFS, ext4 | n | partial | n | varies | y |
| Universal zip-slip + per-entry + aggregate bomb guards | partial | partial | n | n | y |
| Auto-detect + chain (e.g. MSI -> embedded EXE -> UPX -> ...) | n | n | n | n | y |
| License | LGPL-2.1 / BSD | BSD-2 | varies | varies | Apache-2.0 |

### What no other tool does

| Capability | Anyone else | disrobe |
|---|---|---|
| One binary covering 20 ecosystems | n | y |
| Chain auto-detect (PE -> UPX -> rust-demangle, APK -> dex -> jadx + smali, PyInstaller -> PyArmor -> .pyc) | n | y |
| Deterministic output (no AI, no heuristic drift) | partial (some Python decompilers) | y |
| Round-trip recompile verification, mandatory, every emitted file | partial (one Python tool, opt-in) | y |
| Cross-language LLM metadata sidecar (18 categories, 4 packs, 4 serialisation formats) | n | y |
| Content-addressed `.dr` envelope (zero-copy rkyv + postcard cold + BLAKE3 root, 21 ns deserialise) | n | y |
| 50-tool external probe (`disrobe doctor`) | n | y |
| 39-action 7-platform third-party tool installer (`disrobe install <tool>` for Ghidra, UPX, jadx, ILSpy, ...) | n | y |
| Honest per-fixture scores in repo (no "supports X" handwave) | n | y |
| Apache-2.0 across the board (no GPL contamination for downstream commercial users) | n | y |

## Platforms

`disrobe` builds from source on every platform below. The "third-party tool installer" column is what `disrobe install <tool>` uses to fetch optional engines (Ghidra, UPX, jadx, ILSpy, etc.) through the platform's native package manager — it never installs `disrobe` itself.

| Platform                       | Builds | External tool probe | Third-party tool installer    |
| ------------------------------ | ------ | ------------------- | ----------------------------- |
| Windows 10 / 11 (x86-64)       | y      | `disrobe doctor`    | `winget install --silent`     |
| macOS 13+ (ARM64 + x86-64)     | y      | `disrobe doctor`    | `brew install [--cask]`       |
| Linux Debian / Ubuntu          | y      | `disrobe doctor`    | `apt-get install -y`          |
| Linux Fedora / RHEL            | y      | `disrobe doctor`    | `dnf install -y`              |
| Linux Arch                     | y      | `disrobe doctor`    | `pacman -S --noconfirm`       |
| Linux Alpine (musl)            | y      | `disrobe doctor`    | `apk add --no-cache`          |

`disrobe doctor` probes ~50 external tools across decompilers, packers, JVM, .NET, PHP, Erlang / Elixir, Ruby, Lua, Python, container builders, and the mobile + macOS toolchain. Pass `--auto-install` to install everything missing in one shot, or target a single tool with `disrobe install <tool>` (e.g. `disrobe install ghidra`, `disrobe install upx`). Every attempt appends a JSONL trace line to `~/.disrobe/doctor-log.jsonl`.

## Methodology

1. **Frame-tree pre-pass.** Reconstruct the nested source-construct tree from the 3.11+ exception table before the instruction walk. Eliminates the single-pass stack-walker desync that every other Python decompiler suffers from.
2. **Provably-inert normalisations.** 12 of them, applied before the round-trip check: NOP / CACHE / RESUME / EXTENDED_ARG padding, super-instruction fusion, jump-offset shifts, `LOAD_CONST` / `LOAD_NAME` pool order, async cold-handler `CLEANUP_THROW` pair, `__firstlineno__` literal de-dup, retblk and jretleaf canonicalisation. Each one is gated by an adversarial test that proves no real bug is masked.
3. **Round-trip metric.** Every emitted source file is shelled through `py_compile` on the matching interpreter and compared opcode-for-opcode against the original code object. `PERFECT` is byte-identical. `SEMANTIC` is same program, different compiler-version layout. `CODE_DIFF` is a real bug, fixed before ship.
4. **Auto-format pipeline.** Per-language formatter trait: ruff (Python, isolated), prettier (JS / TS), rustfmt (Rust), gofmt (Go), clang-format (C / C++), `dart format`, stylua (Lua), pint (PHP), rufo (Ruby). Disable globally via `--no-format`. A missing formatter falls through to identity emit with a `tracing::warn!` — it never errors the decompile.
5. **`.dr` envelope.** rkyv 0.8 hot payload (zero-copy mmap, bytecheck-validated, 21 ns deserialise) + postcard cold sidecar (schema-evolvable) + BLAKE3 root hash. Cache hits are byte-identical; passes chain offline without network calls.
6. **Five-rung IR ladder.** raw -> disasm -> MIR -> HIR -> surface. Each pass speaks the same vocabulary, so chains compose cleanly across ecosystems.

## Quick start

`disrobe` lives on GitHub and is built from source.  
Requires Rust 1.88+ stable. That is the only dependency to build.

```sh
git clone https://github.com/1-3-7/disrobe
cd disrobe
cargo build --release
./target/release/disrobe doctor          # optional: probe external tools
```

The workspace is 32 members -- 31 ecosystem crates under `crates/` plus an `xtask/` helper. A typical release build sits around 4-6 minutes on commodity hardware. Drop `./target/release/disrobe` (or `disrobe.exe` on Windows) anywhere on your `PATH` and you are done.

Then point `disrobe` at any artefact:

```sh
disrobe py decompile module.pyc --out recovered/
disrobe py deob obfuscated.py --out clean.py --cleanup
disrobe pyarmor unpack protected.py --out unpacked/ --allow-dynamic
disrobe pyinstaller extract onefile.exe --out extracted/
disrobe nuitka extract onefile.exe --out payload/
disrobe js deob bundle.min.js --out clean.js --rename --rename-scope-aware
disrobe js unbundle webpack.bundle.js --target webpack5 --out modules/
disrobe wasm decompile module.wasm --target rust --out lifted.rs
disrobe native decompile app.exe --out decompiled/
disrobe native symbols app.exe --out symbols.json
disrobe jvm decompile App.class --backend cfr --out src/
disrobe jvm decompile app.apk --backend jadx --out src/
disrobe dotnet decompile App.dll --backend ilspy --out src/
disrobe hermes decompile index.android.bundle --out functions/
disrobe macho dump App.framework/App --out symbols/
disrobe macho classdump App.app/App --out classdump/
disrobe lua decompile script.luac --out script.lua
disrobe lua deobfuscate moonsec.lua --family moonsec-v2 --out clean.lua
disrobe php decode app.phar --out unpacked/
disrobe ruby decompile script.rb --out analysis.json
disrobe beam parse module.beam --out chunks.json
disrobe go recover app --out symbols.json
disrobe swift classdump App.app/App --out classdump.json
disrobe as3 disasm flash.swf --out bytecode/
disrobe flutter dump libapp.so --out flutter-layout.json
disrobe envelope create source.py --out source.dr
disrobe envelope verify source.dr
disrobe auto suspect.exe --out recovered/
disrobe auto app.apk --out recovered/
disrobe auto onefile.exe --out recovered/ --emit source,disasm,manifest,signatures
```

Discover the full surface with `disrobe --help`, drill into any subcommand with `disrobe <pass> --help`, or list every optional tool `disrobe` knows how to install for you with `disrobe install --list`. Every ecosystem above also flows through `disrobe auto` (auto-detect + chain) and `disrobe chain` (explicit pass pipeline); the dedicated subcommands are the most direct path when you already know what you're decompiling.

`disrobe auto` chains the full pipeline in one call: `PE -> UPX -> rust-demangle -> recover`, or `APK -> dex -> jadx + smali`, or `pyinstaller -> pyarmor -> .pyc decompile`. Stage outputs land in `out/01-*/`, `out/02-*/`, ..., `out/final/`. For a worked example end-to-end against a live shipped binary, see [docs/usage/discord-e2e.md](docs/usage/discord-e2e.md).

## Usage

```sh
disrobe <pass> <action> <input> [--out <path>] [flags]
```

Global flags on every subcommand:

| Flag | Effect |
|---|---|
| `--json` | Structured JSON output |
| `--ndjson` | Newline-delimited JSON (streaming) |
| `--sarif` | SARIF 2.1.0 (GitHub code scanning, etc.) |
| `--verbose`, `--quiet` | Tracing level |
| `--seed <N>` | RNG seed for any non-deterministic backend |
| `--config <path>` | TOML config file |
| `--no-format` | Disable per-language auto-format |
| `--threads <N>` | Worker pool size |
| `--no-cache` | Bypass the `.dr` envelope cache |
| `--dry-run` | Report what would happen, write nothing |
| `--progress` | Render a TTY progress bar |
| `--llm` | Also emit the structured metadata sidecar (18 categories, 4 packs, 4 serialisation formats) for downstream LLM consumers |
| `--i-have-authorization` | Gate flag for grey-zone commercial protectors. |

Every pass writes a structured manifest alongside the recovered artefact and persists the chain as a `.dr` envelope so subsequent passes resume offline. Output schemas are versioned and published under [`schemas/`](schemas/); Python and TypeScript type stubs ship in [`bindings/python`](bindings/python) and [`bindings/typescript`](bindings/typescript).

## Library use

Beyond the CLI and the HTTP / gRPC servers, `disrobe` ships as a programmatic library for both Rust and Python.

### Rust

Every pass crate is a normal `[lib]`. Add it to your `Cargo.toml` as a git dependency:

```toml
[dependencies]
disrobe-core              = { git = "https://github.com/1-3-7/disrobe" }
disrobe-pass-py-decompile = { git = "https://github.com/1-3-7/disrobe" }
disrobe-binfmt            = { git = "https://github.com/1-3-7/disrobe" }
```

```rust
use disrobe_pass_py_decompile::engine::decompile_pyc;

let pyc_bytes: Vec<u8> = std::fs::read("module.pyc")?;
let recovered = decompile_pyc(&pyc_bytes)?;
println!("{}", recovered.source);
println!("{:?}", recovered.roundtrip_status);
```

### Python

The `disrobe` Python package is a pyo3 cdylib wrapping the same library code the CLI uses. Build it locally with [maturin](https://www.maturin.rs/):

```sh
git clone https://github.com/1-3-7/disrobe
cd disrobe/bindings/python
pip install maturin
maturin develop --release
```

```python
import disrobe

# Recover Python source from .pyc bytes
with open("module.pyc", "rb") as f:
    result = disrobe.py_decompile(f.read(), pack="pack-3")

print(result["source"])
print(result["roundtrip_status"])  # "Perfect" | "Semantic" | "CodeDiff" | "NoInterpreter" | "RecompileFailed"
print(result["llm"]["selection"]["pack"])  # "pack-3" — full LLM metadata bundle
```

Every result dict carries an `llm` key holding the same structured metadata bundle the CLI emits with `--llm` (18 categories, 4 packs). Pass `pack="pack-1"` through `"pack-4"` to control verbosity; omit for the lean default. Where a pass has no LLM emitter wired yet, `llm` is `None` and the docstring notes the v0.10 timeline.

Language-agnostic helpers on the module root:

```python
disrobe.disasm("python", 'print("hello")')   # dis-style listing
disrobe.compile("python", "x = 1\ny = x + 2") # marshalled bytecode bytes
disrobe.parse("python", "def f(): pass")     # AST dict
disrobe.disasm("jvm-class", class_bytes)     # JVM classfile disasm
disrobe.disasm("beam", beam_bytes)           # BEAM disasm
disrobe.disasm("hermes", hbc_bundle)         # Hermes bytecode disasm
disrobe.disasm("wasm", wasm_bytes)           # WASM module pretty-JSON
```

Unsupported (lua / ruby / php / js / ts / go / swift / kotlin) raise `disrobe.UnsupportedLanguage` (a typed subclass of `disrobe.DisrobeError`) with a hint pointing at the equivalent CLI subcommand.

Full Python type stubs ship in [`bindings/python/disrobe/__init__.pyi`](bindings/python/disrobe/__init__.pyi); the 35-function surface and result-dict shapes are statically typed for IDE consumption.

## Legal

Decompilation for security research, interoperability, and recovery of your own source is permitted in most jurisdictions: US DMCA §1201(f), EU Software Directive 2009/24/EC article 6, UK CDPA §50B / 50BA, Canada Copyright Act s.30.61, Australia Copyright Act ss.47D - 47F, Japan Copyright Act art. 47-3 / 47-6. The full posture, with statutory citations and a takedown channel, is in [LEGAL.md](LEGAL.md).

Grey-zone commercial protectors are gated behind the explicit `--i-have-authorization` flag.

## Contribute

- Code of conduct: Contributor Covenant 2.1.
- Contributing guide: [.github/CONTRIBUTING.md](.github/CONTRIBUTING.md).
- Security issues: please open a [private GitHub security advisory](https://github.com/1-3-7/disrobe/security/advisories/new) rather than a public issue.

## License

Apache-2.0. See [LICENSE-APACHE](LICENSE-APACHE) and [NOTICE](NOTICE).
