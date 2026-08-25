![disrobe: deobfuscate, decompile, and unpack with deterministic output ordering](docs/assets/social-card.svg)

disrobe is a Rust command-line suite that decompiles, deobfuscates, and unpacks compiled software. Its catalog spans <!-- m:catalog_ecosystems -->15<!-- /m --> ecosystems: Python, JavaScript and TypeScript, WebAssembly, JVM and Android, .NET, native binaries, Go, Lua, PHP, Ruby, BEAM, Swift and Objective-C, ActionScript 3, mobile runtimes, and shell languages. Default recovery paths do not execute the sample or call a model. A committed determinism gate hashes three real fixture recoveries across Linux, macOS, Windows, and the batch runner at one and four workers.

Every `strong` published number comes from a committed test graded against an independent reference: recovered Python must recompile to equivalent bytecode, recovered Android classes must pass the real JVM verifier, unpacked sections must byte-compare to the original. `coverage-self-reported` rows visibly state when they count disrobe's own output and pin the population they inspect. Where the data is absent from the artifact, disrobe reports the limit instead of guessing past it. Numbers, evidence classes, and reproduce commands live in [evidence/](evidence/).

[![CI](https://github.com/1-3-7/disrobe/actions/workflows/ci.yml/badge.svg)](https://github.com/1-3-7/disrobe/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/1-3-7/disrobe?sort=semver)](https://github.com/1-3-7/disrobe/releases)
[![License: Elastic 2.0](https://img.shields.io/badge/license-Elastic--2.0-blue)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-informational)](https://github.com/1-3-7/disrobe/releases)
[![Docs](https://img.shields.io/badge/docs-1--3--7.github.io%2Fdisrobe-brightgreen)](https://1-3-7.github.io/disrobe/)

## Install

Prebuilt binaries for Windows, Linux (glibc and musl), and macOS, each for x86-64 and ARM64, are on the [Releases page](https://github.com/1-3-7/disrobe/releases) with `SHA256SUMS` and a cosign bundle per archive. Building from source needs Rust 1.95+ stable and nothing else. The in-house paths launch no external programs; backend-capable commands can invoke installed tools when selected explicitly or through `--backend auto`.

```sh
cargo install --git https://github.com/1-3-7/disrobe disrobe-cli
# or, from a clone
cargo build --release              # about 4-6 minutes
./target/release/disrobe doctor    # optional: probe 46 to 51 external tools depending on the platform
```

Optional external backends (Ghidra, CFR, jadx, ILSpy, de4dot) are not required. For `.class` and `.jar` inputs, `jvm decompile --backend auto` uses the first available JVM backend; DEX and APK inputs stay on the in-house path unless an Android backend is selected. `dotnet decompile` also defaults to `--backend auto`, selecting the first available backend in this order: ILSpy, dnSpyEx, dnSpy, then de4dot; its native CIL decompiler runs regardless, including when no external backend is available. Ghidra-backed decompilation runs only through `native decompile --backend ghidra`; `disrobe doctor` may separately launch Ghidra with `-help` while probing installed tools. The slim build, the per-OS notes, and the split between build-time dependencies and the separate toolchains the graded numbers need are in the [installation guide](docs/src/installation.md) and [evidence/README.md](evidence/README.md).

## Quickstart

```sh
disrobe auto suspect.exe --out recovered/             # fingerprint, then chain the whole pipeline
disrobe identify suspect.exe                          # format, packer, and compiler ID
disrobe py decompile module.pyc --out src/            # recover Python source from bytecode
disrobe native unpack packed.exe --out unpacked.bin   # stub-emulator unpack, byte-recovery graded
disrobe webview desktop.exe --out frontend/           # recover Electron, Tauri, or Wails assets
```

For recognized inputs with a viable chain, `disrobe auto` fingerprints the input and composes the whole pipeline in one call: `PE -> UPX -> demangle`, `APK -> dex -> Java`, `PyInstaller -> PyArmor -> .pyc decompile`. With `--capture-stages` each stage lands in `out/01-*/`, `out/02-*/`, ..., `out/final/`. If it recovers no files, it reports that limit and directs you to `disrobe detect` and the relevant dedicated command.

Try it in your browser at [`1-3-7.github.io/disrobe/playground`](https://1-3-7.github.io/disrobe/playground/): the passes compile to WebAssembly and run client-side, and nothing is uploaded.

![demo](docs/src/demo/disrobe-demo.svg)

## Coverage

| Ecosystem | Tier | Headline measured figure | Oracle | Guide |
|---|---|---|---|---|
| Python bytecode | Recover | <!-- m:py_stdlib_pinned_pct -->96.51%<!-- /m --> per code object, 123 of <!-- m:py_stdlib_pinned_modules -->200<!-- /m --> modules whole | strong `[CI]` | [python](docs/src/languages/python.md) |
| PyArmor | Recover | <!-- m:pyarmor_frac -->72 / 72<!-- /m --> manifest-named v8/v9 default-trial wrappers decode one complete header-anchored root `CodeObject` | coverage-self-reported `[CI]` | [python](docs/src/languages/python.md) |
| Python pickle | Recover | <!-- m:pickle_roundtrip_frac -->470 / 470<!-- /m --> reconstructed fixtures re-execute equal | strong `[CI]` | [pickle](docs/src/languages/pickle.md) |
| JVM classfile | Recover | <!-- m:jvm_per_method_count -->131 of 131<!-- /m --> methods recompile | recompile-only `[CI]` | [jvm](docs/src/languages/jvm-android.md) |
| Android DEX | Recover | <!-- m:dalvik_verifier_frac -->118 / 118<!-- /m --> verifier-presented classes | strong `[CI]` | [android](docs/src/languages/jvm-android.md) |
| .NET CIL | Recover | Eazfuscator VM and KoiVM lifted | strong `[CI]` | [dotnet](docs/src/languages/dotnet.md) |
| JavaScript, TypeScript | Recover | obfuscator.io, JS-Confuser, Jscrambler | pass-gated | [js](docs/src/languages/javascript.md) |
| WebAssembly | Recover | <!-- m:wasm_execution_frac -->57 / 57<!-- /m --> eligible functions execute equal | strong `[CI]` | [wasm](docs/src/languages/wasm.md) |
| Native symbols, structure, disasm, IR | Recover | PE / ELF / Mach-O symbols; Windows and OS/2 NE segments, entries, imports, and resources | pass-gated | [native](docs/src/languages/native.md) |
| Native decompile | Recover | x86-64 C and Rust output re-executes equal; AArch64 pseudo-C scalar floating-point output is raw-bit graded, with NaN payloads canonicalized only when both results are NaNs | pass-gated | [decompile](docs/src/languages/native-decompile.md) |
| Native packers | Recover | UPX `.text` and `.pdata` byte-identical | strong `[CI]` | [unpack](docs/src/languages/native-unpack.md) |
| Native VM protectors | Detect-only | handler stream carved, not lifted | pass-gated | [unpack](docs/src/languages/native-unpack.md) |
| Go | Recover | <!-- m:go_typename_count -->838 of 838<!-- /m --> stripped type names | strong `[CI]` | [go](docs/src/languages/go.md) |
| Swift, Objective-C | Recover | committed symbols produce pinned renderings | coverage-self-reported `[CI]` | [swift](docs/src/languages/swift.md) |
| Lua | Recover | IronBrew2 devirt runs equal | strong `[CI]` | [lua](docs/src/languages/lua.md) |
| Ruby | Recover | greeter <!-- m:ruby_greeter_pct -->100%<!-- /m --> under MRI recompile | strong `[CI]` | [ruby](docs/src/languages/ruby.md) |
| PHP | Partial | eval-chain peel, static-key decode loops, Phar decode | pass-gated | [php](docs/src/languages/php.md) |
| BEAM | Recover | <!-- m:beam_recompile_frac -->18 / 19<!-- /m --> stripped Core Erlang cases match `test/0` | strong `[CI]` | [beam](docs/src/languages/beam.md) |
| AS3, Flash | Recover | ABC method-body source | pass-gated | [as3](docs/src/languages/as3.md) |
| Hermes, React Native | Recover | <!-- m:hermes_opcoverage_count -->8 of 8<!-- /m --> functions, no fallback ops | strong `[CI]` | [mobile](docs/src/languages/mobile.md) |
| Flutter Dart AOT | Partial | class and method attribution over a self-authored Dart 3.12.2 corpus, plus a real RustDesk build graded locally | pass-gated | [mobile](docs/src/languages/mobile.md) |
| Haxe HashLink | Recover | class names 100%, methods floor 75% | strong `[CI]` | [scriptlang](docs/src/languages/shell.md) |
| Shell, VBA, XLM | Recover | PowerShell, bash, batch, VBA, Excel 4.0 | pass-gated | [shell](docs/src/languages/shell.md) |
| Perl, R, Tcl | Partial | op-tree, `.rds` round-trip, starkit | pass-gated | [scriptlang](docs/src/languages/shell.md) |
| Nim, Zig, Crystal, D | Partial | demangle plus DWARF aggregates | pass-gated | [native](docs/src/languages/native.md) |
| Containers, firmware | Recover | <!-- roster-breadth:containers-exercised -->41<!-- /roster-breadth --> of <!-- roster-breadth:containers-declared -->102<!-- /roster-breadth --> detected formats write member bytes through the generic entry point from a committed input; LUKS1 is graded through its raw-volume-key entry point | measured `[CI]` | [containers](docs/src/languages/containers.md) |
| Recon, secrets, format ID | Recover | 6 / 6 planted IOC categories | strong `[CI]` | [frisk](docs/src/frisk.md) |

A row's tier is the strongest level any family in that ecosystem reaches, not a promise for every family in it. **Recover** means real recovered output, source or bytes or structure, on the run path. **Partial** means a structural peel or constants only, with the residual stated. **Detect-only** means identification plus a stated reason the rest is not statically present, which is a legitimate triage result rather than a failure. Per-family tiers are in the linked guide and in `disrobe catalog [ecosystem]`, which prints the roster the binary itself carries. Breadth and depth are separate axes: `disrobe identify` and `disrobe catalog` span the full ecosystem list, while recovery depth per family runs from full source recovery down to detect-only.

Roster sizes the binary carries: Python source obfuscators (<!-- m:py_source_obfuscators -->20<!-- /m -->), JS bundlers (<!-- m:js_bundlers -->11<!-- /m -->), JVM and Android obfuscators (<!-- m:jvm_families -->10<!-- /m -->), .NET protectors (<!-- m:dotnet_protectors -->23<!-- /m -->), Packers (29 families), Lua (<!-- m:lua_catalog_entries -->16<!-- /m --> catalog entries), shell obfuscators (<!-- m:shell_families -->19<!-- /m -->), Android RASP (8 vendors).

The [anti-analysis guide](docs/src/anti-analysis.md) documents each defeat capability with the gate behind it: opaque-predicate folding, control-flow deflattening, verified MBA simplification, stack-string emulation, calling-convention and type recovery, indirect-dispatch resolution, and generic VM devirtualization. The [chain runner guide](docs/src/chain.md) covers recursive payload peeling, the encoding and cipher set it reverses, and the structural check that stops a decode from advancing on garbage.

## How the numbers are checked

Two independent labels qualify every figure below. The first is oracle strength, which says what could have rejected a wrong answer.

- `strong`: the result passes an external-equivalence, execution, or byte-identity check against an independent reference. This README reserves the word "proves" for this tier.
- `recompile-only`: the recovered source compiles under the real toolchain; no gate asserts byte-equivalence.
- `coverage-self-reported`: the tool counts its own coverage; no external check grades the count. The tier is lower-confidence and never blends into a `strong` figure.
- `pass-gated`: an in-tree gate exercises the pass on real input, but no single headline figure is published for it. The linked guide names the gate and its strength.

The second is reproducibility. `[CI]` means a committed test gate reproduces the number on every run. `[local]` means the input is kept out of the tree by license or size; the stated command still reproduces the number, just not inside CI. The two axes are orthogonal, so a `strong` figure can be `[local]` and a `[CI]` figure can be self-reported.

Each `[CI]` number links to a committed corpus or fixture, a runnable reproduce command, and a public CI log. Descriptors and rendered results live under [`evidence/`](evidence/); [`.github/workflows/ci.yml`](.github/workflows/ci.yml) and [`.github/workflows/evidence.yml`](.github/workflows/evidence.yml) run the gates that produce them. The evidence harness renders its report from committed descriptors, [`xtask/data/recovery.json`](xtask/data/recovery.json), and measured JSON.

## Benchmarks

### Strong

Read the first three Python rows together. A module counts as recovered only when every one of its code objects recompiles to equivalent bytecode. A module typically holds dozens of code objects, so a small per-object miss rate compounds into a large per-module one. To know whether a whole readable module comes back, use the whole-module figure of 123 of <!-- m:py_stdlib_pinned_modules -->200<!-- /m --> modules (61.5%), not the per-object 96.51%. That gap is the center of the evaluation rather than a footnote, and the [whitepaper](docs/src/architecture/whitepaper.md) works through it.

The Oracle column names the independent reference in a few words. What that reference is and how it can reject a wrong answer is in the cited test and in the linked guide.

| Metric | Measured | Oracle | Reproduce |
|---|---|---|---|
| Python `.pyc`, full 3.14 stdlib | <!-- m:py_stdlib_full_pct -->95.09%<!-- /m --> per code object `[local]` | recompile-equivalence, over a population CI does not run | `crates/disrobe-pass-py-decompile/tests/harness/py_arbitrary_measure.py` |
| Python `.pyc`, pinned 200-module corpus | <!-- m:py_stdlib_pinned_pct -->96.51%<!-- /m --> per object, floor 96.51% `[CI]` | recompile-equivalence | `crates/disrobe-pass-py-decompile/tests/arbitrary_recompile_gate.rs` |
| Python `.pyc`, whole-module exact | 123 of <!-- m:py_stdlib_pinned_modules -->200<!-- /m --> modules recompile whole, floor 123 `[CI]` | recompile-equivalence | `crates/disrobe-pass-py-decompile/tests/arbitrary_recompile_gate.rs` |
| Python legacy 1.0-3.7 | <!-- m:py_legacy_count -->150 of 191<!-- /m --> gate-verified `[CI]` | recompile or token match | `crates/disrobe-pass-py-decompile/tests/legacy_recompile.rs` |
| Pickle safety | 102 / 102 fixtures classify `[CI]` | pickletools semantics | `crates/disrobe-pass-pickle/tests/corpus.rs` |
| Pickle reconstruction roundtrip | 470 / 470 re-execute equal, floor 100% `[CI]` | CPython re-execution | `crates/disrobe-pass-pickle/tests/roundtrip.rs` |
| Android DEX, committed corpus | <!-- m:dalvik_verifier_frac -->118 / 118<!-- /m --> verifier-presented classes clean, 317 re-hosted bodies clean `[CI]` | real JVM verifier | `crates/disrobe-pass-jvm/tests/dalvik_verifier_gate.rs` |
| .NET Eazfuscator VM | 67 / 67 instructions lifted, ordered-CIL match `[CI]` | independent clean DLL | `crates/disrobe-pass-dotnet/tests/real_eazvm.rs` |
| .NET KoiVM | 6 / 6 bodies lifted, structural recovery >= 75% `[CI]` | independent clean build | `crates/disrobe-pass-dotnet/tests/real_koivm.rs` |
| .NET protectors | <!-- m:dotnet_protectors -->23<!-- /m --> classified, ConfuserEx2 decrypted `[CI]` | plaintext-absent check | `crates/disrobe-pass-dotnet/tests/confuserex2_full.rs` |
| WebAssembly, execution-equiv | <!-- m:wasm_execution_frac -->57 / 57<!-- /m --> eligible functions equal, 6 byte-identical `[CI]` | wasmtime differential | `crates/disrobe-pass-wasm-deob/tests/semantic_differential.rs` |
| BEAM, stripped Core Erlang | <!-- m:beam_recompile_frac -->18 / 19<!-- /m --> committed cases recompile, preserve exports, and match `test/0` `[CI]` | real `erlc` and `erl`, OTP 27.3.4 | `crates/disrobe-pass-beam/tests/erlc_recompile_equivalence.rs` |
| WebAssembly obfuscator helpers | <!-- m:wasm_direct_helpers -->4<!-- /m --> cataloged direct-helper families; 3 transformations run through `wasm deob`, while Tigress-via-Emscripten is detected only `[CI]` | parser and execution gates | `crates/disrobe-pass-wasm-deob/tests/obfuscators_e2e.rs` |
| Lua IronBrew2 2.7.0 devirt | runs equal, standard and MAX mode `[CI]` | real-`lua` differential | `crates/disrobe-pass-lua/tests/ironbrew2_real_oracle.rs` |
| Ruby YARV, greeter | <!-- m:ruby_greeter_pct -->100%<!-- /m --> `[CI]` | MRI recompile, opcode multiset | `crates/disrobe-pass-ruby/tests/yarv_recompile_oracle.rs` |
| Ruby YARV, megafile | <!-- m:ruby_megafile_pct -->98.67%<!-- /m --> of 23966 opcodes `[CI]` | MRI recompile, opcode multiset | `crates/disrobe-pass-ruby/tests/yarv_recompile_oracle.rs` |
| Go type-name recovery | <!-- m:go_typename_count -->838 of 838<!-- /m --> type names, stripped `[CI]` | typelinks survive `-s -w` | `crates/disrobe-pass-go/tests/go_typemeta.rs` |
| Go BuildInfo and garble undo | BuildInfo recovered, `-literals` rebuilt `[CI]` | real toolchain output | `crates/disrobe-pass-go/tests/go_buildinfo_oracle.rs` |
| HashLink (Haxe `.hl`) | class names 100%, method names floor 75% `[CI]` | names vs the original `.hx` | `crates/disrobe-pass-scriptlang/tests/real_hashlink_decompile.rs` |
| Native UPX | `.text` and `.pdata` byte-identical, floor 96.0% `[CI]` | byte-identity | `crates/disrobe-pass-native/tests/upx_unpack_all.rs`, `nrv2b_content_section_byte_recovery_meets_floor` |
| Native packers, MPRESS | `.text` >= 90%, `.rdata` >= 85% `[CI]` | RVA-aligned recovery | `crates/disrobe-pass-native/tests/mpress_gauntlet.rs` |
| Native packers, Yoda's Crypter | `.rsrc`, `.text`, `.data` byte-identical `[CI]` | byte-identity | `crates/disrobe-pass-native/tests/packer_real_samples.rs` |
| Native packers, ASPack and PECompact | content and rebuilt IAT >= 98% byte-identical `[CI]` | RVA-aligned recovery | `crates/disrobe-pass-native/tests/aspack_pecompact_phase2.rs` |
| Native packers, MEW | structural loaded-image recovery `[CI]` | RVA-aligned recovery | `crates/disrobe-pass-native/tests/mew_unpack.rs` |
| Native packers, committed pairs | nspack 57721 / 60060, fsg 55263 / 60060, petite 86986 / 89648 `[CI]` | content-section bytes | `crates/disrobe-pass-native/tests/committed_packer_byte_recovery.rs` |
| Native packers, larger local samples | no figure published, `corpus/native/packers/petite/megafile_DirCmp.exe` uncommitted `[local]` | whole-image comparison | `crates/disrobe-pass-native/tests/petite_unpack.rs` |
| Native packers, kkrunchy | kkrunchy and kkrunchy classic payloads `[CI]` | payload byte-identity | `crates/disrobe-pass-native/tests/kkrunchy_unpack.rs` |
| Native stub-emulator unpack | dispatch and decode round-trip `[CI]` | stub-emu equivalence | `crates/disrobe-pass-native/tests/stub_pack_oracle_roundtrip.rs` |
| Hermes HBC v96 | <!-- m:hermes_opcoverage_count -->8 of 8<!-- /m --> functions, 0 fallback `[CI]` | op-coverage, source bodies | `crates/disrobe-pass-mobile/tests/real_hermes_sample.rs` |
| Hermes production bundle | <!-- m:hermes_functions -->122,633<!-- /m -->-function parse `[local]` | parse scale, gitignored input | `crates/disrobe-pass-mobile/tests/real_hermes_discord.rs` |
| APK secrets vs apkleaks | 8 / 8 planted secrets vs 5 / 8 `[CI]` | planted ground truth | `cargo run -p disrobe-bench-head-to-head` |
| frisk IOC detection | 6 / 6 planted IOC categories `[CI]` | planted ground truth | `crates/disrobe-core/tests/frisk_gauntlet.rs` |
| Container / archive / firmware extraction | <!-- roster-breadth:containers-exercised -->41<!-- /roster-breadth --> of <!-- roster-breadth:containers-declared -->102<!-- /roster-breadth --> detected formats reached through the generic entry point by a committed input `[CI]`; LUKS1 has a separate tracked decryption fixture | extraction over the committed corpus | `crates/disrobe-cli/tests/container_breadth.rs`, `crates/disrobe-binfmt/tests/real_luks1.rs` |
| Cross-platform determinism | 3 / 3 real fixtures byte-identical, 3-OS matrix `[CI]` | BLAKE3 hash equality | `crates/disrobe-cli/tests/determinism_cross_platform.rs` |
| Native taint, Juliet CWE-78 | 93 / 190 flows recalled (48.9%), 0 false positives, gcc 16.1.0 -O2 `[local]` | NIST SARD Juliet Test Suite's own manifest; CI does not provision the corpus | `crates/disrobe-taint/tests/graded_corpus.rs` |

![Measured recovery by ecosystem](docs/assets/recovery.svg)

Each bar states how it was checked, in colour and again in the tag beside it. A lighter bar means a
stronger reference could have rejected the number. A filled mark means a committed gate reproduces
the figure on every run, and a hollow mark means the input stays outside the tree and the stated
command reproduces it locally. Each tier comes from the evidence descriptor that owns the figure, so
a bar cannot be drawn stronger than the reference behind it.

The Python figures count code objects, not modules. The full-stdlib row covers <!-- m:py_stdlib_full_count -->17378 of 18276<!-- /m --> objects across <!-- m:py_stdlib_full_modules -->574<!-- /m --> modules; the pinned row covers <!-- m:py_stdlib_pinned_count -->6067 of 6286<!-- /m --> objects across <!-- m:py_stdlib_pinned_modules -->200<!-- /m --> modules, and the same legacy gate reaches <!-- m:py_legacy_local_count -->166 of 191<!-- /m --> locally. The Go row is measured on a stripped go1.26.3 fixture, its gate pins the count and holds the ratio above a <!-- m:go_typename_pct -->85%<!-- /m --> floor, and `go_garble_undo.rs` covers the garble leg beside it.

The Android committed-corpus row is measured on small methods; <!-- m:dalvik_link_skipped_count -->37 of 155<!-- /m --> classes are link-skipped and ungraded, and the real-apk row further down carries the production scale. The WebAssembly execution row covers the functions that can be run at all, which is a smaller population than the 133-function corpus: a function needs a callable signature and no host imports before wasmtime can run it. The .NET Eazfuscator row has a second `[CI]` leg in which the recovered CIL re-injects to byte-identical stdout; CI provisions the required .NET runtime.

The BEAM figure is scoped to the committed `test/0` observation in each case. The test compiles the original Erlang source with OTP 27.3.4, strips both `Dbgi` and `Docs`, recovers through the Core Erlang path, recompiles the recovered source, compares exports, and then compares `test/0` exit status and stdout under real `erl`. It does not claim equivalence for every input to every export. CI enforces this gate on Linux; macOS and Windows report it as unmeasured when Erlang is absent.

The Swift row is pinned against a committed fixture's own symbol table and expected in-process renderings. The parity leg against the reference `swift-demangle` runs only where that tool is installed; CI neither requires nor provisions it, so it is not a guaranteed CI-graded public comparison. HashLink also parses the whole HLB image byte-exact, 336 functions and 421 types on the committed fixture. The PyArmor row is limited to 72 manifest-named v8/v9 default-trial wrapper/runtime pairs. Its test statically decrypts each body and requires its header-anchored marshal stream to decode as one complete root `CodeObject`; it does not compare source, emitted `.pyc` bytes, semantic or execution behavior, or external-tool output. The container row's assertion is `published_container_counts_match_this_enum`, which binds the 35 to the formats a committed input drives to member bytes rather than to the roster that declares the extractors; the rest have no committed input, so they are unverified rather than shown to fail. The six planted IOC categories frisk is graded on are endpoints, manifest findings, URLs, IPv4, email, and `.onion`.

Native UPX recovers about 96% of the whole image beyond the two byte-identical sections. For the committed packer pairs, `.text` and `.data` are byte-identical for all three families, and nspack's `.rdata` is byte-identical too. One packed-and-original pair per family is committed, so each figure reproduces from a clean checkout. The same decoders score lower on the whole-image measure over larger uncommitted vendor samples, with the content sections holding up far better than the whole image. `fsg_unpack.rs` and `nspack_byte_recovery.rs` sit beside the cited petite test, but no figure is published for them because nothing there reproduces or is pinned. Determinism is also checked across worker-pool sizes: the same fixtures run through `disrobe auto <dir>`'s batch runner at `--jobs 1` and `--jobs 4` produce identical bytes, and that batch runner is the one real concurrent code path in the CLI.

### Recompile-only

| Metric | Measured | Oracle | Reproduce |
|---|---|---|---|
| JVM classfile `recompile-only` | <!-- m:jvm_per_method_count -->131 of 131<!-- /m --> methods recompile error-free, floor 131 `[CI]` | real `javac`, JDK 25 | `crates/disrobe-pass-jvm/tests/decompile_recompile_rate.rs` |

Nothing asserts bytecode-equivalence for that row. The recovered source compiles, which is a weaker statement than the Strong tier makes.

### Self-reported coverage

| Metric | Measured | Oracle | Reproduce |
|---|---|---|---|
| Android DEX, real APKs `coverage-self-reported` | <!-- m:dalvik_body_pct -->99.6%<!-- /m --> of methods that declare a code item `[local]` | self-reported, gitignored apks | `crates/disrobe-pass-jvm/tests/dex2jar_realworld_apks.rs` |
| Android DEX, real APKs, count `coverage-self-reported` | <!-- m:dalvik_body_frac -->83609 / 83943<!-- /m --> `[local]` | self-reported, gitignored apks | `crates/disrobe-pass-jvm/tests/dalvik_realworld_body_attest.rs` |
| WebAssembly, op-coverage `coverage-self-reported` | <!-- m:wasm_opcoverage_count -->1034 of 1034<!-- /m --> opcodes across 38 parseable modules `[CI]` | wasm-tools 1.250.0 supplies the denominator; lowering is self-counted | `crates/disrobe-pass-wasm-deob/tests/external_op_denominator.rs` |
| Swift symbol rendering `coverage-self-reported` | committed symbols produce pinned renderings `[CI]` | binary `LC_SYMTAB` membership with pinned in-process output | `crates/disrobe-pass-swift-objc/tests/swift_hello_symbol_pin.rs` |
| PyArmor v8/v9 default-trial wrappers `coverage-self-reported` | <!-- m:pyarmor_frac -->72 / 72<!-- /m --> manifest-named wrappers decode one complete header-anchored root `CodeObject` `[CI]` | self-reported structural check | `crates/disrobe-pass-pyarmor/tests/static_unpack_corpus.rs` |

That figure is the total across all three apks and not any one of them. The per-apk split, and a separate verifier-attested population with its own smaller denominator, are in the [Android guide](docs/src/languages/jvm-android.md).

The recovered bodies that can be presented to the verifier are attested at <!-- m:dalvik_body_attested_frac -->2985 of 2998<!-- /m -->, graded by real `java -Xverify:all` over bodies rather than methods, which is a different and smaller population than the method-coverage figure above.

The WebAssembly denominator is external and frozen: `wasm-tools 1.250.0` disassembles each committed `.wat` and its per-function instruction inventory is checked in, keyed by the fixture's BLAKE3, so a decoder that stops seeing opcodes scores lower rather than shrinking the population it is divided by. The two decoders agree instruction for instruction, 1034 accounted against 1034 counted. The row stays self-reported because the numerator is still disrobe counting the opcodes it lowered, and a lowering rule firing is not the same as the lowering being right. The 2 corpus files outside the 38 are the ones `wasm-tools` rejects too, pinned with its own error text.

<details>
<summary>Reproduce every number</summary>

Every figure above traces to the cited test gate or runner and either [`xtask/data/recovery.json`](xtask/data/recovery.json) or a measured JSON file under [`evidence/results/measured/`](evidence/results/measured/). To regenerate the public report and re-check those sources:

```sh
./evidence/run.sh                          # render evidence/results/EVIDENCE.md + index.json
cargo run -p xtask -- evidence --check     # drift gate: rendered numbers must match their sources and floors must hold
cargo run -p xtask -- evidence --list      # every descriptor: ecosystem, strength, [CI]/[local], measured, floor
```

To re-run an individual gate, use the `Reproduce` command in its row, for example:

```sh
cargo test -p disrobe-pass-py-decompile --test arbitrary_recompile_gate   # Python .pyc recompile-equivalence
cargo test -p disrobe-pass-jvm --test dalvik_verifier_gate                # Android -Xverify:all
cargo test -p disrobe-pass-wasm-deob --test semantic_differential --features sandbox   # WASM wasmtime differential
DISROBE_REQUIRE_ERLANG=1 cargo test -p disrobe-pass-beam --test erlc_recompile_equivalence -- --nocapture   # BEAM OTP differential
cargo run  -p disrobe-bench-native-unpack                                 # native packer byte-recovery table
```

[evidence/README.md](evidence/README.md) documents the build/runtime dependency boundary and the offline-vs-network reproducibility tiers.

</details>

## Head-to-head

![Python decompilation coverage by version against competing tools](docs/assets/python-versions.svg)

The head-to-head runner compares the same committed input with pinned tool versions and records the reference each row uses. A missing same-input runner is not treated as a win. The runner is [`benches/head-to-head/`](benches/head-to-head/); pinned tools live in [`evidence/competitors/`](evidence/competitors/).

| Surface | `disrobe` | Leading tool | Result | Reproduce |
|---|---|---|---|---|
| <!-- evidence-pair:apk-jadx-cfr:jar -->JVM classfile | 181 / 181 methods recompile | CFR 0.152: 152 / 166 methods recompile | `disrobe` leads on clean methods and clean rate | `cargo run --locked -p disrobe-bench-head-to-head -- --check --only apk-jadx-cfr`<!-- /evidence-pair --> |
| <!-- evidence-pair:apk-jadx-cfr:dex -->Android DEX | 57 / 163 methods recompile | JADX 1.5.5: not certified: 295 methods emitted | no lead: the JADX output is not certified (the producer exited nonzero) | `cargo run --locked -p disrobe-bench-head-to-head -- --check --only apk-jadx-cfr`<!-- /evidence-pair --> |
| APK secrets | 8 / 8 planted secrets | apkleaks 2.6.3: 5 / 8 | `disrobe` catches the AWS secret key, Basic credential, and JWT apkleaks misses | `cargo run -p disrobe-bench-head-to-head` |

Missing rows are not implied wins. Every surface without a same-input runner stays in the edge table below until one exists.

<details>
<summary>Edge comparison</summary>

Matchups without a same-input runner are tracked in [evidence/edge-comparison.md](evidence/edge-comparison.md) until one exists. A missing row there is not an implied win.

</details>

## Limits

Recovery is bounded by what the compiler or protector left in the artifact. `disrobe` reports those bounds rather than rounding them away.

**Native VM-protector devirtualization.** VMProtect, Themida, Yoda's Protector, and the same class of native packers (WinLicense, Enigma, Armadillo, Obsidium, PE-Protector, PELock) assemble their handler stream at run time from a per-machine key that is not present in the file. `disrobe` detects all of them and structurally carves the handler stream for VMProtect, Themida, and Yoda's Protector.

**Runtime-only decrypt keys.** PyArmor v3-v5, ionCube, SourceGuardian, modern Zend Guard, ILProtector, MaxToCode, and Themida-.NET derive their key in a native loader or a live process, and it was never written into the artifact. `disrobe` detects and identifies the envelope for all of them, plus a partial `op_array` skeleton for the products with a statically-keyed legacy tier.

**One-way name hashing.** Seedless garble stores `base64(hmac-sha256(name, seed))` with the seed absent in `-trimpath` builds. Structure, types, and control flow recover regardless; names are canonicalized, not restored.

**Vendor-firmware runtime key.** The Airoha OTP-AES key is not present in the carved firmware image, so the format is detected and its members carved, and nothing further.

**Encrypted volumes.** `disrobe extract` detects LUKS1 and, without a key, returns a successful typed wall that names the cipher, mode, digest, iteration count, and missing raw volume key. `--luks1-raw-volume-key-file PATH` accepts a bounded key file, while `--luks1-raw-volume-key-file -` reads the bounded key from standard input. This route supports only LUKS1 `aes-cbc-plain` with a 128-, 192-, or 256-bit raw volume key and SHA-1, SHA-256, or SHA-512 PBKDF2 header digests. It does not unlock passphrases or keyslots and does not accept XTS or LUKS2. A detached LUKS1 header requires its separately stored encrypted payload. VeraCrypt and TrueCrypt may be undetectable without a key; headerless dm-crypt has no header to detect.

PyArmor BCC native blobs are carved and passed to an in-tree static lift under `--allow-bcc`. The dedicated PyArmor command and the path-aware `disrobe auto` route emit `bcc/bcc-recovery.json`, `bcc/bcc-pseudo-c.c`, and `bcc/bcc-recovered.py`. The JSON uses `disrobe.pyarmor.bcc.recovery/v1` and embeds the existing `disrobe.pyarmor.bcc.function_map/1` map. It records modeled functions, unmodeled native disassembly, and typed blob refusals without executing the sample. The lift uses the Microsoft x64 ABI for Windows x86-64, the System V ABI for Linux x86-64, and AAPCS64 for Darwin ARM64. Nuitka, Nim, Zig, and Crystal native bodies are compiled machine code present in the artifact rather than absent; their dedicated recovery paths report what they can lift instead of inheriting a claim from the PyArmor path.

Bytecode-to-source is structurally faithful but never byte-identical: `.class`, `.dex`, and CIL erase local names, generics, comments, and exact formatting.

Native decompilation runs on an in-tree backend, which is the default: x86-64 to C or to Rust, AArch64 to pseudo-C, and it rejects a form it cannot recover rather than guessing at one. The two grading levels are separate and are not interchangeable. Leaf-level recompile equivalence is gated by `pseudo_c_leaf_oracle.rs` and `pseudo_rust_leaf_oracle.rs`; whole-program by `pseudo_c_wholeprog_oracle.rs` and `pseudo_rust_wholeprog_oracle.rs`; the register-only return channel by `return_channel_corpus.rs`. AArch64 is behind x86-64, emits no Rust, and its whole-program path covers validated direct same-image calls in linked ELF inputs only. No committed benchmark compares this backend with Ghidra or IDA, so this page states no ranking against them. Ghidra remains available through `native decompile --backend ghidra`, and `native export --format ghidra|ida|json` hands either one unpacked, symbol-rich input. Each of these five files grades against a real gcc or clang and falls back to an unmeasured skip when neither is on PATH; setting `DISROBE_REQUIRE_NATIVE_TOOLCHAIN=1`, which CI does, turns that skip into a failure instead.

## CLI surface

`disrobe --help` lists direct analysis commands and ecosystem command families. Representative commands:

```sh
disrobe auto sample.bin --out recovered/ --capture-stages   # detect and chain, keeping every stage
disrobe catalog native                                      # supported families and recovery tier
disrobe py decompile module.pyc --out src/                  # CPython 1.0-3.15
disrobe pyarmor unpack protected.py --out out/ --allow-bcc  # static unpack and BCC publication
disrobe js unbundle app.bundle.js --out src/                # un-webpack, source-map reconstruction
disrobe wasm decompile module.wasm --target rust            # also ts, wat, c
disrobe jvm decompile app.apk --out src/                    # in-house Dalvik decompiler is the default
disrobe dotnet decompile App.dll --out src/                 # in-house CIL to C#/F#/VB
disrobe native unpack packed.exe --out unpacked.bin         # in-house decoders plus x86 stub emulator
disrobe native decompile app.exe --backend native           # x86-64 to C or Rust; AArch64 to pseudo-C
disrobe native disasm stripped.bin --emit cfg-dot           # function discovery plus per-function CFG
disrobe native export packed.exe --format ghidra            # rebuilt PE plus a Ghidra/IDA/JSON symbol map
disrobe query packed.exe string-decoders                    # queryable IR over stripped code
disrobe capabilities packed.exe                             # MITRE ATT&CK and MBC with per-match evidence
disrobe taint malware.exe --source recv --sink system       # source-to-sink dataflow over the shared IR
disrobe go recover app --out symbols.json                   # pclntab symbols, BuildInfo, garble undo
disrobe lua decompile script.luac --out script.lua          # 5.1-5.4, LuaJIT, Luau, IronBrew2 devirt
disrobe shell deob payload.ps1 --out clean.ps1              # PowerShell, bash, batch, VBA, Excel 4.0
disrobe extract firmware.bin --out carved/ --recursive      # carve every supported container format
disrobe webview desktop.exe --out frontend/                  # Electron ASAR, Tauri, or Wails frontend assets
disrobe frisk recovered/ --format sarif                     # secrets, endpoints, buckets, IOCs
disrobe prowl example.com --subs --format json              # the one command that touches the network
disrobe report out/ --format html                           # self-contained offline forensic report
```

The complete surface, flag by flag, is in the [command reference](docs/src/cli/reference.md); the flags that apply everywhere are in [global flags](docs/src/cli/global-flags.md). `disrobe passes` lists the passes, `disrobe catalog [ecosystem]` lists every recognized family and its tier, and `disrobe explain <code>` looks up any `DR-` diagnostic with its cause and fix.

## Library, bindings, and daemon

The CLI is a thin layer over the same crates, so a TUI, an IDE plugin, a web service, or a batch engine drives the full pass set directly. Each pass is its own Rust crate over shared `disrobe-core` and `disrobe-ir` types. `import disrobe` gives a pyo3 `abi3` module for Python 3.9+ that ships `.pyi` and `py.typed`. It takes bytes in, returns typed report objects, and never touches the filesystem. `disrobe serve` speaks HTTP, gRPC, and LSP, and `disrobe serve --mcp` exposes the same operations as Model Context Protocol tools. Signed WebAssembly Component plugins verify and execute under the sandbox as a library capability; the CLI does not yet dispatch an analysis pass through one.

See the [library guide](docs/src/library.md), the [Python bindings](docs/src/python-bindings.md), and [the daemon](docs/src/cli/serve.md).

## Architecture

![Chain runner stages from raw bytes through the IR ladder to verified source](docs/assets/ir-ladder.svg)

![End-to-end recovery chains from packed, mobile, and frozen inputs to oracle-verified source](docs/assets/architecture.svg)

`disrobe` is a chain runner over single-purpose passes that lower every artifact onto one shared intermediate-representation ladder. Detection fingerprints the input, and the chain runner recursively unpacks and routes it. Each pass recovers what is statically present and reports the rest with a measured score.

```text
   Raw  -->  Disasm  -->  MIR  -->  HIR  -->  Surface
   bytes     opcodes      mid       high      source
```

Unpacking and decryption operate at Raw, where byte recovery lives. Disassembly produces Disasm. Decompilers do their structural work at MIR and HIR, then render Surface for the checks available to that pass. `disrobe-nir-lift` contains bytecode front ends for AVM2, BEAM, CIL, Dalvik, JVM, Lua, Python, WebAssembly, and YARV; native lifting enters through the disassembler. `disrobe query`, `disrobe capabilities`, and `disrobe taint` consume the normalized IR through direct CLI commands. `disrobe passes` prints the separate set of pass IDs that the standard CLI build can reach through `disrobe auto`.

The shared artifact layer can persist recovered state as a `.dr` envelope: an rkyv payload, a postcard metadata sidecar, and a BLAKE3 root over both. Chain runs also write `chain.json` and `recovery.json`; `--capture-stages` records the exact bytes written by each stage. Commands that implement metadata bundles accept `--metadata-pack-1` through `--metadata-pack-4`; `--llm` is a compatibility alias for pack 4. The bundle is deterministic data for downstream tooling and does not invoke a model.

The [architecture guide](https://1-3-7.github.io/disrobe/latest/architecture.html) has the full model, the [IR ladder page](docs/src/ir-ladder.md) the rung definitions, and the [whitepaper](https://1-3-7.github.io/disrobe/latest/architecture/whitepaper.html) the deterministic CPython decompiler, the typed-AST x86-64 lift, managed-VM devirtualization, and the grading discipline behind every claim.

## Safety posture

Every default path is pure static analysis and never executes the sample. The pickle suite is symbolic and never unpickles. Only the PyArmor v6/v7 dynamic hook executes sample code, behind `--allow-dynamic` with a watchdog. `--allow-bcc` permits only in-tree static analysis and does not execute the sample or invoke external tools. Run the dynamic hook inside a sandbox. The parsing surface is hardened against malformed and oversized input. See [Forensics and malware-safety posture](https://1-3-7.github.io/disrobe/latest/forensics-safety.html) and the [threat model](https://1-3-7.github.io/disrobe/latest/threat-model.html).

## Documentation

Full docs site: [`1-3-7.github.io/disrobe`](https://1-3-7.github.io/disrobe/), covering the architecture, the IR ladder, the chain runner, per-language guides, [webview desktop recovery](docs/src/languages/webview.md), the Python-bindings reference, the complete CLI reference, and the safety posture. The book source is under [`docs/`](docs/). [Per-protector stances](https://1-3-7.github.io/disrobe/latest/legal.html#per-protector-stances-on-file) records the legal posture behind a gray-zone recognizer escalating to a full peel.

Integrations: a [GitHub Action](docs/src/integrations/github-action.md) that scans a path or glob and uploads SARIF to code scanning, a [pre-commit hook](docs/src/integrations/pre-commit.md) that blocks a commit on a packed or obfuscated artifact, an [MCP server](docs/src/integrations/mcp.md), and [editor plugins](docs/src/integrations/editor-plugins.md) for VS Code, IDA Pro, Ghidra, and Binary Ninja.

## Legal

Decompilation for security research, interoperability, and recovery of your own source is permitted in most jurisdictions (17 U.S.C. section 1201(f), Directive 2009/24/EC Art. 6, CDPA 1988 ss. 50B-50BA, and equivalents in CA/AU/JP). The full posture with statutory citations and a takedown channel is in [LEGAL.md](LEGAL.md). Legally sensitive recovery paths that need an explicit authorization assertion expose `--i-have-authorization` and refuse without it.

## Contributing

Contributions are welcome; see the [contributing guide](.github/CONTRIBUTING.md). For security issues, open a [private advisory](https://github.com/1-3-7/disrobe/security/advisories/new) rather than a public issue. See [SECURITY.md](SECURITY.md).

## License

[Elastic License 2.0](LICENSE), source-available. Companies and security researchers may use, copy, modify, and distribute `disrobe` for free; attribution is mandatory, so keep the author, copyright, and licensing notices intact. You may not provide `disrobe` to third parties as a hosted or managed service, and you may not remove or obscure any licensing, copyright, or other notices. The `disrobe` name and marks are reserved and granted no rights by the license. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
