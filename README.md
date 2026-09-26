<img alt="disrobe: recover source, structure, and bytes from compiled software" src="docs/assets/social-card.png" width="1280">

# Disrobe

[![Latest release](https://img.shields.io/github/v/release/1-3-7/disrobe)](https://github.com/1-3-7/disrobe/releases/latest)
[![Documentation](https://img.shields.io/badge/docs-1--3--7.github.io%2Fdisrobe-blue)](https://1-3-7.github.io/disrobe/)
[![License: Disrobe Source-Available 1.1](https://img.shields.io/badge/license-source--available-red)](LICENSE)

**Disrobe is a static decompiler, deobfuscator, and unpacker.** It strips packing and obfuscation from compiled software one layer at a time and recovers the source code or the original bytes underneath.

Give `disrobe auto` an executable, an app package, a script, or a firmware image. It names each layer (installer, archive, packer, freezer, protector, obfuscator, bytecode), removes it with the matching recovery pass, and runs again on what that pass produced until no pass recognizes what is left. One Rust binary covers Python, JavaScript and WebAssembly, Java and Android, .NET, native PE, ELF, and Mach-O code, Go, Lua, PHP, Ruby, Erlang and Elixir, ActionScript, shell scripts and Office macros, React Native and Flutter apps, installers, and firmware. `disrobe catalog` lists the <!-- m:catalog_family_total -->170<!-- /m --> packers, protectors, obfuscators, and bytecode families it recognizes across <!-- m:catalog_ecosystems -->15<!-- /m --> ecosystems.

The engines are built in. Python bytecode decompiles without a Python installation, JavaScript recovery needs no Node.js, and the Java, Android, and .NET decompilers need no JVM or .NET SDK; with the default `--backend auto`, `jvm decompile` and `dotnet decompile` use an installed external decompiler first. Disrobe does not launch the program it analyzes unless you pass `--allow-dynamic`, which applies only to PyArmor v6 and v7. The [safety model](#safety-model) lists the bounded interpreters that evaluate code taken from an input and the host tools Disrobe starts.

It is built for malware analysts, reverse engineers, incident responders, CTF players, and security researchers.

**License:** [Disrobe Source-Available License 1.1](LICENSE). Personal hobby projects and learning, unpaid independent security research, nonprofit education and research, and journalism are free, as the license defines them. Any use by or for a company requires a [paid license](COMMERCIAL.md).

[Quick start](#quick-start) · [What it recovers](#what-it-recovers) · [Measured results](#measured-results) · [How it works](#how-it-works) · [Safety model](#safety-model) · [Documentation](https://1-3-7.github.io/disrobe/)

## Quick start

Download the archive for your platform from [GitHub Releases](https://github.com/1-3-7/disrobe/releases/latest), check it against `SHA256SUMS`, and put `disrobe` (`disrobe.exe` on Windows) on your `PATH`. Then run:

```sh
disrobe identify suspect.exe                # compiler, packer, and protector, with evidence
disrobe auto suspect.exe --out recovered/   # remove the layers Disrobe can recover
disrobe context --out recovered/            # what each pass recovered, and at what confidence
```

Recorded output of `identify` and the unpacking step, run on a UPX-packed Rust program committed to this repository (`corpus/native/packers/upx/hello.packed.nrv2b.exe`):

```text
$ disrobe identify hello.packed.exe
format: pe64 (64-bit) subsystem=windows-cui
packer     UPX  (96%)  -> disrobe native unpack
             - [section UPX0] UPX characteristic section
             - [section UPX1] UPX characteristic section
             - [section UPX2] UPX characteristic section
             - [byte scan] UPX packer magic
...

$ disrobe native unpack hello.packed.exe --out recovered/hello.bin
native unpack: OK
  input:        hello.packed.exe
  packer:       upx
  status:       Implemented
  packed_size:  53248
  recovered:    116810 bytes
  wrote:        recovered/hello.bin
```

The unpacking benchmark recovers the same file and compares it with the original build: the `.text` section is byte-identical, 73,160 bytes with no differences ([unpacking measurements](benches/native-unpack/results.md)).

Release archives cover Windows (x86-64, ARM64), macOS (x86-64, ARM64), and Linux (x86-64 and ARM64 with glibc, static x86-64 with musl). Each archive has a separate cosign signature bundle, and [SECURITY.md](SECURITY.md#sigstore-transparency-log) explains the check. Building from source needs the Rust toolchain pinned in `rust-toolchain.toml` (1.96.1; the minimum supported version is 1.95) and a C toolchain for native dependencies:

```sh
git clone https://github.com/1-3-7/disrobe
cd disrobe
cargo build --locked --release -p disrobe-cli --bin disrobe
```

The [installation guide](docs/src/installation.md) covers feature flags and the optional external backends. Run `disrobe doctor` to probe 46 to 51 external tools depending on the platform and see which optional backends are installed.

## What it recovers

Each row names the formats Disrobe reads and the protection it removes. Where `disrobe catalog` lists a family, the level shown is the catalog's. Families named first are recovered. *Partial* families are peeled as far as the input allows, and the result names what is left. *Detect only* families are identified, and the result states why the rest cannot be recovered, usually because a key exists only at run time. A name in **bold** is graded on output of the real tool, committed to this repository; the other names are graded on samples written for the tests, or are only detected. Each ecosystem links to its guide.

| Ecosystem | Formats and bytecode | Packers, protectors, and obfuscators |
|---|---|---|
| [Python](docs/src/languages/python.md) | CPython 3.8 to 3.15 `.pyc` and marshal data; PyPy 3.9 and 3.10; MicroPython `.mpy`; Jython; IronPython; Brython; Cython modules. Freezers: **PyInstaller** onefile (onedir and encrypted PYZ are read too), **Nuitka** (onefile, standalone, module), **shiv**, **Briefcase**, cx_Freeze, py2exe, pex, and PyOxidizer (experimental) | **PyArmor** v8 and v9, **SourceDefender** v15 and earlier, and source obfuscators (<!-- m:py_source_obfuscators -->20<!-- /m --> schemes, counting the partial ones and both pyobfuscate.com schemes): **Berserker**, **BlankOBF**, **Kramer/Specter**, **Manglify**, **ObfuXtreme**, **Patchwork**, **PlusOBF**, **pyminifier**, **pyobfuscate.com**, **PyObfuscator**, Jawbreaker, Oxyry, Wodx, Xindex, pyc-zipper, the online obfuscator family. *Partial:* PyArmor v6 and v7, **python-obfuscator**, pyobfus, Pypacker. *Detect only:* PyArmor v3 to v5; SourceDefender v16, whose key exists only at run time |
| [JavaScript and TypeScript](docs/src/languages/javascript.md) | Minified and obfuscated source; bundles from **webpack**, **Vite**, **Rollup** (including its SystemJS format), **esbuild**, **Parcel**, **Bun**, Turbopack, Browserify, and Rolldown; source maps; V8 cached data (`.jsc`, bytenode) from Node 18, 20, 22, and 24; Node SEA, nexe, nw.js; Electron ASAR; **Tauri** and **Wails** apps ([webview guide](docs/src/languages/webview.md)); Deno `eszip` | **obfuscator.io** (javascript-obfuscator), **JS-Confuser**, **aaencode**, **jjencode**, JSFuck, Dean Edwards Packer, JSFiretruck. *Partial:* **Jscrambler**, **jsobfu**; JSDefender and Arxan (Digital.ai) static transforms, only with `--i-have-authorization`. *Detect only:* PACE |
| [WebAssembly](docs/src/languages/wasm.md) | `.wasm` to WAT, Rust, TypeScript, C, or a JSON summary; Component Model; GC types | *Partial:* Jscrambler WASM, Wobfuscator, wasm-mixer; Tigress (through Emscripten) and wasm-name-obfuscator, detected and classified |
| [Java and Android](docs/src/languages/jvm-android.md) | `.class` files from Java 1.1 to 25, JAR, DEX 035 to 039, APK, AAB, APKM, XAPK, ODEX, single-DEX OAT; `AndroidManifest.xml`, `resources.arsc`, APK signatures v2 to v4; Kotlin metadata | **Allatori**, **BlackObfuscator**, Zelix KlassMaster (ZKM), DashO, DexGuard. *Partial:* **ProGuard** and **R8** (names from `mapping.txt`), **yGuard**, SkidSuite2 and **Skidfuscator** (number obfuscation), JBCO, Stringer (the committed Stringer output is detected, not decrypted). *Detect only:* runtime markers of Promon SHIELD, Appdome, Zimperium, Guardsquare, and DexProtector; 360 Jiagu, SecNeo (Bangcle), and other packers that decrypt the DEX at start-up |
| [.NET](docs/src/languages/dotnet.md) | Assemblies to C#, F#, or VB pseudo-source; ReadyToRun; Native AOT; single-file bundles | <!-- m:dotnet_protectors -->23<!-- /m --> protectors: **ConfuserEx2**, **KoiVM** (ConfuserEx VM), Eazfuscator.NET. *Partial:* **ConfuserEx**, **Obfuscar**, **BitMono**, .NET Reactor, SmartAssembly, CryptoObfuscator, Skater, Spices.Net, Agile.NET, ArmDot, Babel, DeepSea, Dotfuscator (and CE), Goliath, DotNetPatcher, NetCryptor. *Detect only:* ILProtector, MaxToCode, Themida (.NET wrapper) |
| [Native code](docs/src/languages/native.md) | PE32 and PE64, EFI, ELF, Mach-O (thin and fat), COFF, MZ, NE, LE, LX. C pseudo-source from x86-64, AArch64, ARM32, and MIPS32, and Rust for pure integer leaf functions on x86-64 ([decompiler](docs/src/languages/native-decompile.md)); 32-bit x86 disassembly. Symbols and language structures of Rust, C++, Delphi, Nim, Zig, Crystal, and D binaries; DWARF, PDB, and STABS debug data | <!-- m:native_catalog_entries -->27<!-- /m --> packers and protectors ([unpacking](docs/src/languages/native-unpack.md)): **UPX**, **MPRESS**, **FSG**, **NSPack**, **Petite**, **kkrunchy**, **ASPack**, **PECompact**, **MEW**, sRDI, Yoda's Crypter (with the original image). *Partial:* Donut, ASProtect, Morphine, NeoLite, nPack, PolyCryptor, Warzone Crypter. *Detect only:* VMProtect, Themida and WinLicense, Enigma Protector, Obsidium, Armadillo, PELock, PE-Protector, Yoda's Protector. Obfuscation: **OLLVM** flattening, bogus control flow, and instruction substitution; mixed boolean-arithmetic (MBA) expressions; **guardian-rs** virtualization; **obfuscxx** strings; Tigress flattening. *Detect only:* **obfus.h**, **Cryptify** (rust-obfuscator), **obfusheader.h**, AutoIt scripts |
| [Go](docs/src/languages/go.md) | Go binaries for Windows, Linux, and macOS, go1.15 to go1.26: function names, types, module data, BuildInfo, `embed.FS` files | **garble**: literals recovered on x86-64; standard-library names that garble leaves unhashed are kept, and hashed names stay hashed, because reversing them needs the build seed |
| [Lua](docs/src/languages/lua.md) | Lua 5.1 to 5.4, LuaJIT 2.1, Luau, and Garry's Mod Lua (GLua) bytecode | **IronBrew2**. *Partial:* **Prometheus**, **WeAreDevs**, **luaobfuscator.com**, Hercules, MoonSec V1 to V3, PSU, AztupBrew, Boronide, DarkSec, SLua. *Detect only:* Luraph |
| [PHP](docs/src/languages/php.md) | Source, `eval` chains (base64, gzinflate, rot13, XOR) whose keys are literals in the file, Phar archives | Better PHP Obfuscator, **YAK Pro** (yakpro-po), FOPO. *Detect only:* ionCube, SourceGuardian, Zend Guard |
| [Ruby](docs/src/languages/ruby.md) | YARV instruction sequences (opcode tables for Ruby 2.6 to 3.4), mruby RITE bytecode | *Partial:* OCRA, RubyScript2Exe. *Detect only:* JRuby, TruffleRuby |
| [Erlang and Elixir](docs/src/languages/beam.md) | `.beam` modules and EZ archives, to Erlang, Elixir, or Core Erlang | None |
| [ActionScript 3](docs/src/languages/as3.md) | SWF (FWS, CWS, ZWS) and ABC bytecode | *Detect only:* secureSWF, DoSWF, Kindi, Irrfuscator, swfLock |
| [Shell and Office](docs/src/languages/shell.md) | PowerShell, Bash, Batch; VBA p-code (VBA5, VBA6, and VBA7); Excel 4.0 (XLM) macros in BIFF8 and BIFF12; PDF JavaScript, launch actions, and embedded files; Perl, R, Tcl, Haxe, and Windows Script Host (identified) | Invoke-Obfuscation (token, AST, string, encoding, compress), **Invoke-Stealth**, **Chameleon**, PowerHell, psobf, **Bashfuscator**, **node-bash-obfuscate**, Bash `IFS` and `eval` indirection, Batch `%random%` and `set` indirection, VBA stomping. *Partial:* Invoke-Obfuscation launcher, ISESteroids |
| [Mobile apps](docs/src/languages/mobile.md) | React Native Hermes bytecode (lifted for eight HBC versions from v62 to v96); Flutter Dart kernel; Flutter `libapp.so` AOT snapshots (declarations and ARM64 disassembly for Dart 3.12.2, structure for other versions); React Native, Cordova, Capacitor, NativeScript, and Xamarin or .NET MAUI packages | None |
| [Swift and Objective-C](docs/src/languages/swift.md) | Mach-O Swift and Objective-C metadata (class dump, demangling), fat binaries, dyld shared caches (tested on a synthetic cache; `auto` reads split caches, `macho dyldcache` only the named file) | **SwiftShield**, given its rename map |
| [Pickle and model files](docs/src/languages/pickle.md) | Pickle protocols 0 to 5; PyTorch, TorchScript, and NumPy files that embed pickles; pickle polyglots | Malicious pickles: `pickle safety` traces reducer calls without running them and matches dangerous callables. A benign verdict means that no known pattern matched |
| [Installers, archives, firmware](docs/src/languages/containers.md) | <!-- m:containers_formats -->103<!-- /m --> container formats, among them ZIP, 7z, RAR, CAB, MSI, NSIS, **Inno Setup**, InstallShield, Squirrel, DMG, PKG, DEB, RPM, AppImage, Snap, Flatpak, MSIX, ISO, VHD, VHDX, WIM, SquashFS, ext4, JFFS2, UBI, YAFFS2, Android sparse images, Docker and OCI images, UEFI firmware volumes, and vendor firmware such as Netgear CHK and TRX | Inno Setup extraction is byte-exact on official 4.0.9, 4.1.6, 6.3.3, and 7.1.0 installers; encrypted installers are refused. LUKS1 volumes open with an `aes-cbc-plain` raw volume key |

## Measured results

Most figures below come from a committed test that compares Disrobe's output with an independent reference: a compiler, a runtime, a verifier, the original file, or another tool's output. Rows graded `coverage-self-reported` count Disrobe's own output. The populations are small and named, so a figure describes its population and not every input of its kind. CI last measured the push and weekly rows at commit `d9bb5f59`, in runs whose only failures were the `graphs` job and the macOS and Windows shards of one test group. The latest release, v0.10.6, predates some of these figures, so build from source to reproduce one. The [evidence records](evidence/results/EVIDENCE.md) give the fixtures, reference, and reproduction command for each figure that has a descriptor.

The grades: `strong` means an independent reference could have rejected the output (execution, byte identity, a verifier, or an external tool); `recompile-only` means a real compiler accepted the output, with no behavioural check; `coverage-self-reported` means the count comes from Disrobe's own counters. In the **Runs** column, push is every push to `main`, weekly is the scheduled weekly run and release tags, and local means that no CI job provisions the input, so the committed test re-measures the figure where it runs.

**Python decompilation, per interpreter.** Each interpreter compiles the same pinned list of <!-- m:py_stdlib_pinned_modules -->200<!-- /m --> standard-library modules. A code object counts when the recovered source recompiles to the same normalized opcode structure. Jump targets and most operands are not compared, and modules an interpreter does not ship leave its denominator, so the rows are not a ranking.

| Interpreter | Modules | Matching code objects | Rate | Grade | Runs |
|---|---|---|---|---|---|
| CPython 3.8.20 | 154 | 4,508 of 5,088 | 88.60% | `recompile-only` | weekly |
| CPython 3.9.25 | 157 | 4,935 of 5,233 | 94.30% | `recompile-only` | weekly |
| CPython <!-- m:py_band_310_interpreter -->3.10.20<!-- /m --> | <!-- m:py_band_310_modules -->161<!-- /m --> | <!-- m:py_band_310_frac -->5229 / 5458<!-- /m --> | <!-- m:py_band_310_rate -->95.80%<!-- /m --> | `recompile-only` | push |
| CPython <!-- m:py_band_311_interpreter -->3.11.15<!-- /m --> | <!-- m:py_band_311_modules -->172<!-- /m --> | <!-- m:py_band_311_frac -->5442 / 5638<!-- /m --> | <!-- m:py_band_311_rate -->96.52%<!-- /m --> | `recompile-only` | weekly |
| CPython <!-- m:py_band_312_interpreter -->3.12.13<!-- /m --> | <!-- m:py_band_312_modules -->177<!-- /m --> | <!-- m:py_band_312_frac -->5420 / 5659<!-- /m --> | <!-- m:py_band_312_rate -->95.77%<!-- /m --> | `recompile-only` | push |
| CPython <!-- m:py_band_313_interpreter -->3.13.14<!-- /m --> | <!-- m:py_band_313_modules -->190<!-- /m --> | <!-- m:py_band_313_frac -->5732 / 5966<!-- /m --> | <!-- m:py_band_313_rate -->96.07%<!-- /m --> | `recompile-only` | push |
| CPython <!-- m:py_band_314_interpreter -->3.14.5<!-- /m --> | <!-- m:py_stdlib_pinned_modules -->200<!-- /m --> | <!-- m:py_stdlib_pinned_count -->6077 of 6286<!-- /m --> | <!-- m:py_stdlib_pinned_pct -->96.67%<!-- /m --> | `recompile-only` | weekly |
| CPython <!-- m:py_band_315_interpreter -->3.15.0b4<!-- /m --> | <!-- m:py_band_315_modules -->199<!-- /m --> | <!-- m:py_band_315_frac -->6227 / 6480<!-- /m --> | <!-- m:py_band_315_rate -->96.09%<!-- /m --> | `recompile-only` | weekly |

A wider CPython 3.14.5 population of <!-- m:py_stdlib_full_modules -->574<!-- /m --> core modules gives <!-- m:py_stdlib_full_count -->17396 of 18276<!-- /m --> matching code objects (<!-- m:py_stdlib_full_pct -->95.18%<!-- /m -->, local). [Pinned result](evidence/results/py-stdlib-recompile.md) · [Full-population result](evidence/results/py-stdlib-full.md).

**Other ecosystems.**

| Recovery | Result | Reference | Grade | Runs |
|---|---|---|---|---|
| Java class files to Java | <!-- m:jvm_per_method_count -->131 of 131<!-- /m --> top-level methods of the EdgeCases corpus recompile | Real `javac` | `recompile-only` | weekly |
| Java behaviour | 117 / 131 of the same methods behave identically; 8 diverge and 6 cannot be driven in isolation | A real JVM | `strong` | weekly |
| Android DEX to Java | <!-- m:dalvik_verifier_frac -->118 / 118<!-- /m --> verifier-presented classes pass; <!-- m:dalvik_link_skipped_count -->37 of 155<!-- /m --> classes are link-skipped and ungraded | `java -Xverify:all` | `strong` | weekly |
| .NET assemblies to C# | 18 / 35 complete EdgeCases types recompile standalone | Roslyn `csc` | `recompile-only` | weekly |
| WebAssembly | <!-- m:wasm_execution_frac -->57 / 57<!-- /m --> eligible functions return the same values, traps, and first 4,096 bytes of linear memory | wasmtime | `strong` | weekly |
| Stripped BEAM modules | <!-- m:beam_recompile_frac -->19 / 19<!-- /m --> modules recompile, keep their exports, and print the same `test/0` result | Erlang/OTP 27.3.4 | `strong` | weekly |
| Go type names, stripped binary | <!-- m:go_typename_count -->838 of 838<!-- /m --> names | None: the names come from the binary's own type data | `coverage-self-reported` | weekly |
| Go function names, stripped binaries | From 88.78% (darwin/amd64) to 100% (windows/386) on seven platforms; the missing names are assembly entry points and linker symbols that a stripped image does not carry | `go tool nm` on the unstripped builds | `strong` | weekly |
| Hermes bytecode v96 | <!-- m:hermes_opcoverage_count -->8 of 8<!-- /m --> functions lift with their original names and no fallback operations | A real `hermesc` build and its source | `strong` | weekly |
| Lua, IronBrew2 2.7.0 | Standard and MAX output recover to programs that run identically | The original programs under Lua | `strong` | weekly |
| JavaScript, JS-Confuser 2.0.1 | Recovered programs print byte-identical output | The original programs under node 24.16.0 | `strong` | weekly |
| .NET, Obfuscar 2.2.50 | <!-- m:dotnet_obfuscar_hidden_strings -->15 / 15<!-- /m --> hidden string values recovered byte for byte | The unprotected build's strings | `strong` | weekly |
| Native unpacking | UPX (NRV2B and LZMA), FSG, NSPack, and Petite recover a `.text` section byte-identical to the original on the committed Hash (FSG, NSPack) and hello (UPX, Petite) pairs; a second FSG pair recovers 31,171 of 33,870 `.text` bytes | The original builds committed beside the packed files | `strong` | weekly |
| Tauri and Wails frontends | Every embedded file of real Tauri 1.8.3, Tauri 2.11.5, and Wails 2.13.0 builds matches its source file | The frontend trees the builds were made from | `strong` | weekly |
| Pickle reconstruction | <!-- m:pickle_roundtrip_frac -->470 / 470<!-- /m --> reconstructed fixtures pass re-execution equality checks ([Result](evidence/results/pickle-roundtrip.md)) | CPython re-execution | `strong` | weekly |
| Pickle disassembly and classification | 102 / 102 committed fixtures | CPython `pickletools` | `strong` | weekly |
| Ruby YARV, Ruby 3.4.9 | Opcode-name recall after recompiling: greeter <!-- m:ruby_greeter_pct -->100%<!-- /m -->, megafile <!-- m:ruby_megafile_pct -->98.67%<!-- /m -->; order and operands are ignored | MRI recompilation | `recompile-only` | weekly |
| PyArmor v8 and v9 | <!-- m:pyarmor_frac -->72 / 72<!-- /m --> default-trial wrappers (PyArmor 8.5.12 and 9.2.5) decrypt and decode a complete root code object | Disrobe's own count; source equivalence is not measured | `coverage-self-reported` | weekly |

**Against other tools on the same input.** Each pair runs Disrobe and another tool on the same input and grades both outputs the same way. In the Java rows each tool emits its own set of regions, so the counts are not a ranking; the APKLeaks row counts exact matches of eight secrets planted in one APK.

| Tool and input | Disrobe | Other tool |
|---|---|---|
| <!-- evidence-pair:apk-jadx-cfr:dex:summary -->JADX 1.5.5 · Android DEX | 157 / 228 emitted regions compile clean | 281 / 303 emitted regions compile clean<!-- /evidence-pair --> |
| <!-- evidence-pair:apk-jadx-cfr:jar:summary -->CFR 0.152 · JVM classfile | 181 / 181 emitted regions compile clean | 152 / 166 emitted regions compile clean<!-- /evidence-pair --> |
| APKLeaks 2.6.3 · planted-secrets APK | 8 / 8 planted secrets | 5 / 8 planted secrets |

These comparisons are re-measured weekly and on pushes that touch their evidence paths. [Inputs, raw tool output, and reproduction commands](benches/head-to-head/results.md).

<details>
<summary><strong>Reproduction rows and further measurements</strong></summary>

| Input | Disrobe emitted regions | Other tool emitted regions | Population boundary | Reproduce |
|---|---|---|---|---|
| <!-- evidence-pair:apk-jadx-cfr:dex -->Android DEX | 157 / 228 emitted regions compile clean | JADX 1.5.5: 281 / 303 emitted regions compile clean | no cross-tool ranking: each tool has its own emitted-region population | `cargo run --locked -p disrobe-bench-head-to-head -- --check --only apk-jadx-cfr`<!-- /evidence-pair --> |
| <!-- evidence-pair:apk-jadx-cfr:jar -->JVM classfile | 181 / 181 emitted regions compile clean | CFR 0.152: 152 / 166 emitted regions compile clean | no cross-tool ranking: each tool has its own emitted-region population | `cargo run --locked -p disrobe-bench-head-to-head -- --check --only apk-jadx-cfr`<!-- /evidence-pair --> |

| Surface | Result | Grade | Runs |
|---|---|---|---|
| Native unpacking, MPRESS 2.19 | The recovered `.text` section is byte-identical to the original build | `strong` | local (`benches/native-unpack`) |
| Mixed boolean-arithmetic | 316 expressions with held-out originals. CI requires at least 180 answers within a 2-second budget per expression, no answer refuted by an external solver, and at least one proved equal; the answer count varies with machine load | `coverage-self-reported` | weekly |
| OLLVM flattening | <!-- m:native_cff_cover_states -->9<!-- /m --> of <!-- m:native_cff_dispatcher_states -->9<!-- /m --> dispatcher states reached in two committed functions from one compiler and optimization level | `coverage-self-reported` | weekly |
| Luau opcode table | <!-- m:luau_opcode_lift_count -->86 of 88<!-- /m --> declared opcodes lifted; `BREAK` and `NEWCLASSMEMBER` decode but are not lifted | `coverage-self-reported` | weekly |
| Android, three real open-source APKs | <!-- m:dalvik_body_frac -->83662 / 83943<!-- /m --> method bodies lowered; <!-- m:dalvik_body_attested_frac -->2988 of 2998<!-- /m --> bodies placed in isolated carriers also pass the JVM verifier | `coverage-self-reported` | local |
| Containers | <!-- roster-breadth:containers-exercised -->42<!-- /roster-breadth --> generic extraction routes write member bytes from an input committed to this repository | `coverage-self-reported` | weekly |

[Evidence records](evidence/results/EVIDENCE.md).

</details>

## How it works

`disrobe auto` fingerprints the input, runs the pass with the highest confidence, then fingerprints that pass's output and every child it extracted, and repeats. It stops when no pass clears the confidence threshold, when a content hash repeats, or at the depth limit (8 by default, `--max-depth`). Given a directory, it processes the files under it recursively, skipping hidden directories and symbolic links. The end-to-end tests follow chains such as a PyInstaller archive whose `.pyc` children go on to the decompiler, a PyArmor v8 wrapper inside a PyInstaller archive, and a UPX-packed Rust executable that unpacks and then yields demangled Rust symbols.

```sh
disrobe auto app.exe --out recovered/ --capture-stages   # keep each stage's exact output
disrobe auto samples/ --out batch/ --jobs 4              # a whole directory, four workers
disrobe chain module.pyc --chain py.decompile --out src/ # a pass list you choose
disrobe passes                                           # every registered pass
```

Each `auto` or `chain` output directory holds `chain.json` (`disrobe.chain/v1`), which records the topology, the chosen passes, their confidence, and a BLAKE3 hash of every stage, and `recovery.json` (`disrobe.recovery/v1`), which records each pass's verdict and timing. `auto` also writes `report.sarif`, whose run properties embed a STIX 2.1 bundle. The global flags `--json`, `--ndjson`, and `--sarif` switch output to JSON, streaming JSON, or SARIF 2.1.0, and `disrobe report` renders a finished run as text, JSON, Markdown, HTML, or SARIF.

Given the same input, flags, build, and installed formatters, the recovered files are the same whatever the worker count, unless one of the time limits below ends a step early; the weekly run compares `--jobs 1` with `--jobs 4` on a batch of three fixtures. The run records (`chain.json`, `recovery.json`, `report.json`, and `report.sarif`) also record each pass's duration and the worker count, and their timestamps are fixed only when `SOURCE_DATE_EPOCH` is set. These steps stop on elapsed time rather than a step count, so a heavily loaded machine or a higher `--jobs` can change their output: JavaScript string-array probes run one at a time across all workers, are refused after waiting 30 seconds for their turn, and stop after 4 seconds (a rotation search after 180 seconds); the JSFuck, aaencode, jjencode, and JSFiretruck decoders stop after 30 seconds; the Dalvik interpreter after 750 milliseconds; PHP decoding loops after 2 seconds; the two Go garble scans after 8 seconds each; formatters after 5 seconds; and mixed boolean-arithmetic simplification and VM devirtualization after 250 milliseconds per solver query, 5 seconds in total, 750 milliseconds per SMT check, and one minute per binary for the devirtualization that `native decompile` runs unless `--no-devirt` is given.

[Pass list](docs/src/passes.md) · [Chain runner](docs/src/chain.md) · [Reading a result](docs/src/reading-a-result.md) · [Batch processing](docs/src/cli/batch.md) · [Run reports](docs/src/cli/report.md)

## Safety model

Disrobe is built to open hostile files, but it is not a sandbox. Run it on inputs you are allowed to analyze, in an environment you would trust with them.

| What runs | When | Bound |
|---|---|---|
| The program under analysis | Only `pyarmor unpack --allow-dynamic`, for PyArmor v6 and v7 | A watchdog stops the Python process it starts; processes that the wrapper spawns are not contained |
| JavaScript taken from the input: string-array decoders, jsobfu character folding, JSFuck, aaencode, jjencode, JSFiretruck | By default in `js deob` and in `auto` | The embedded Boa engine, with `fetch` removed. String-array probes stop at 4 seconds and 100,000 loop iterations (a rotation search at 180 seconds and 10 million), recursion depth 256, a 256 KiB prelude, and 4 MiB of generated script. The esoteric decoders stop waiting after 30 seconds, but their worker thread is not killed |
| Packer stubs and string decoders taken from the input | By default, when a packer needs stub emulation, and in `strings` unless `--no-decode` is given | The in-house x86 emulator, with a step cap per packer and 256 MiB per mapping |
| .NET, Java, and Dalvik string-decryption methods taken from the input | By default, for the protectors that need them | In-process interpreters: 4 million steps for CIL, up to 6 million for JVM bytecode, and 2 million steps and 750 milliseconds for Dalvik |
| PHP taken from the input, in loader and decode loops | By default in PHP recovery | The in-house PHP subset interpreter: 4 million steps, 64 MiB of heap, 16 MiB of output, 2 seconds |
| JS-Confuser control-flow VM bytecode | By default when JS-Confuser's VM is detected | The in-house VM interpreter: 200,000 steps |
| garble literal thunks | By default on x86-64 garble binaries | The in-house x86-64 emulator: 200,000 steps per thunk, 8 seconds per scan |
| A local CPython of the matching version, if one is on `PATH` | By default in `py decompile`, `pyfreeze extract`, and `nuitka decompile` | Compiles the recovered source; 60 seconds (120 for Nuitka); `py decompile --no-roundtrip` skips it. The interpreter starts in the current directory without `-I`, so a `py_compile.py` there would run: do not run Disrobe from inside an extracted sample tree |
| Installed archive tools: unrar, 7z, bsdtar, pkgutil, and hdiutil, which mounts the DMG or ISO image | When the built-in reader cannot extract a RAR, PKG, DMG, or ISO file | 180 seconds per extraction |
| Ghidra headless | `native decompile --backend ghidra` | 10 minutes |
| Package managers | `install` and `doctor --auto-install` | 10 minutes per package |
| Installed external decompilers: ILSpy, dnSpy, dnSpyEx, de4dot, CFR, Vineflower, Procyon, JD, Krakatau, JADX, dex2jar | `dotnet decompile` and `jvm decompile` with the default `--backend auto`, or a backend you name | `--timeout-secs`, 300 seconds by default |
| Installed code formatters: ruff, prettier, rustfmt, gofmt, clang-format, and others | By default, on recovered source, when the formatter is on `PATH` | The source goes to the formatter on stdin; 5 seconds per call; the output stays unformatted when the formatter is missing or fails |
| Installed optional tools, with `--version` | `doctor` and `bug-report` | 3 seconds per tool |

Only the PyArmor v6/v7 dynamic hook runs sample code natively, behind `--allow-dynamic` with a watchdog. `--allow-bcc` permits only in-tree static analysis and does not execute the sample or invoke external tools.

Apart from `prowl`, which queries public web archives and threat-intel services, `serve`, which listens for requests, and `install`, `install-deps`, and `doctor --auto-install`, which download tools, commands make no network requests. Parsers bound their input size, allocation, recursion, and output, with two known exceptions: JavaScript unbundling limits neither its input size nor its module count or output size, and the committed 7.35 MiB JSFuck file `corpus/js/jsfuck/obfuscated.megafile.js` overflows the stack of the embedded JavaScript engine and ends the process, as the [behaviour gate](benches/perf/README.md) records. `--i-have-authorization` gates the commercial JavaScript protector transforms, `lua deob` for MoonSec v3 and IronBrew2, `php decode` for ionCube, SourceGuardian, and Zend Guard input, and the decryption-key metadata category; `auto` applies the Lua transforms without it. The [threat model](docs/src/threat-model.md) describes the trust boundaries, and [SECURITY.md](SECURITY.md) explains how to report a vulnerability.

## Use it from other tools

| Integration | How |
|---|---|
| MCP | An MCP server over stdio gives MCP clients the recovery and navigation tools ([guide](docs/src/integrations/mcp.md)) |
| Python | Typed bindings (`import disrobe`), built from source with maturin ([guide](bindings/python/README.md)) |
| GitHub Actions | `uses: 1-3-7/disrobe@<tag>` downloads the release binary, runs a command on a path, and uploads SARIF ([guide](docs/src/integrations/github-action.md)) |
| pre-commit | The `disrobe` hook fails a commit that stages a packed or obfuscated artifact ([guide](docs/src/integrations/pre-commit.md)) |
| Disassemblers and editors | Integrations for VS Code, IDA Pro, Ghidra, and Binary Ninja ([guide](docs/src/integrations/editor-plugins.md)); `native export` rebuilds a supported packed PE with its entry point restored and writes a symbol map for Ghidra, for IDA, or as JSON |
| Browser | The [playground](https://1-3-7.github.io/disrobe/playground/) runs a WebAssembly build of Disrobe, and the input stays on your device (files up to 64 MiB) |
| Rust | Depend on the workspace crates by git revision ([library guide](docs/src/library.md)) |

## Commands

`disrobe <command> --help` is the reference for your build, and the [CLI reference](docs/src/cli/reference.md) covers every subcommand. `disrobe explain <code>` describes a `DR-*` diagnostic.

| Task | Commands |
|---|---|
| Recover | `auto`, `chain`, `extract`, `webview`, `pyarmor`, `pyinstaller`, `pyfreeze`, `nuitka` |
| One language or runtime | `py`, `js`, `wasm`, `native`, `jvm`, `apk`, `dotnet`, `hermes`, `flutter`, `mobile`, `macho`, `swift`, `go`, `lua`, `php`, `ruby`, `beam`, `as3`, `shell`, `pickle` |
| Identify and scan | `identify`, `detect`, `catalog`, `strings`, `scan`, `ioc`, `indicators`, `frisk`, `behavior`, `capabilities`, `yara` |
| Navigate and compare | `query`, `semdiff`, `diff` |
| Reports and evidence | `context`, `report`, `status`, `envelope`, `verify`, `guard`, `annot`, `rename` |
| Setup and help | `doctor`, `init`, `config`, `completions`, `man`, `explain`, `passes`, `bug-report` |
| Scheduled for removal | `serve`, `plugin`, `prowl`, `install`, `install-deps`, `self-update`, `taint`, `vulnmatch` |

## Limits

- Compilation discards comments, formatting, and many names and types, so recovered source is a reconstruction. The tables above say how each kind of output is checked.
- Recognition is broader than recovery. A catalog match can come with partial output, so read the level and the result's own report.
- A key derived at run time, a payload fetched from the network, or a name-hashing seed cannot be recovered from a file that does not contain it.
- Commercial virtualizers such as VMProtect, Themida, and WinLicense are detected, not unpacked or devirtualized.
- Native decompilation covers x86-64, AArch64, ARM32, and MIPS32. ARM32 and MIPS32 output is checked for the operations it contains, not for equivalent behaviour, and 32-bit x86 is only disassembled.
- Scale is unmeasured for large inputs: the largest committed WebAssembly module is 17,173 bytes, and no figure covers bundles in the tens of megabytes.

## Documentation

- [Documentation site](https://1-3-7.github.io/disrobe/), with the [quickstart](docs/src/quickstart.md), the [result guide](docs/src/reading-a-result.md), and the [family catalog](docs/src/catalog.md).
- [Evidence harness](evidence/README.md) and [evidence records](evidence/results/EVIDENCE.md).
- [Contributing guide](.github/CONTRIBUTING.md), [threat model](docs/src/threat-model.md), [security policy](SECURITY.md), and [legal considerations](LEGAL.md). Whether you may analyze a given artifact depends on your circumstances.

## License

Disrobe is proprietary, source-available software under the [Disrobe Source-Available License, Version 1.1](LICENSE). The [relicensing notice](RELICENSING-NOTICE.md) explains how it relates to earlier terms.

Personal hobby projects, personal learning, unpaid independent security research by individuals, nonprofit education and research, and bona fide journalism are free, as defined in the license. **Any use by or for a company requires a paid license.** See [commercial licensing](COMMERCIAL.md).

**Required credit:** This work used Disrobe, created by 1-3-7: https://github.com/1-3-7/disrobe

Forks other than contribution forks, reposting, rebranding, resale, hosting, and competing development are prohibited. The software is provided as is, at the user's own risk. See [attribution](ATTRIBUTION.md), [contributor terms](CONTRIBUTING-LICENSE.md), the [license summary](LICENSE-SUMMARY.md), and the [notice](NOTICE).

Copyright (c) 2025-2026 1-3-7. All rights reserved.
