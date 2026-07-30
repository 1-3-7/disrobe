![disrobe: decompile, deobfuscate, and unpack compiled software, deterministically](docs/assets/social-card.svg)

disrobe is one static Rust binary that decompiles, deobfuscates, and unpacks compiled software across 20+ ecosystems: Python, JVM and Android, .NET, JavaScript and WebAssembly, Lua, Go, Ruby, PHP, shell, and native x86-64/AArch64. By default it never executes the sample, runs no model, and produces byte-identical output on every machine.

Every published number comes from a committed test graded against an independent reference, never against disrobe's own output: recovered Python must recompile to equivalent bytecode, recovered Android classes must pass the real JVM verifier, unpacked sections must byte-compare to the original. Where the data is absent from the artifact, disrobe reports the limit instead of guessing past it. Numbers, oracles, and reproduce commands live in [evidence/](evidence/).

[![CI](https://github.com/1-3-7/disrobe/actions/workflows/ci.yml/badge.svg)](https://github.com/1-3-7/disrobe/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/1-3-7/disrobe?sort=semver)](https://github.com/1-3-7/disrobe/releases)
[![License: Elastic 2.0](https://img.shields.io/badge/license-Elastic--2.0-blue)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-informational)](https://github.com/1-3-7/disrobe/releases)
[![Docs](https://img.shields.io/badge/docs-1--3--7.github.io%2Fdisrobe-brightgreen)](https://1-3-7.github.io/disrobe/)

## Install

Prebuilt binaries for Windows, Linux (glibc and musl), and macOS, each for x86-64 and ARM64, are on the [Releases page](https://github.com/1-3-7/disrobe/releases) with `SHA256SUMS` and a cosign bundle per archive. Building from source needs Rust 1.95+ stable and nothing else; at run time `disrobe` links or invokes no Python, Node, JVM, wasmtime, Lua, or external tool.

```sh
cargo install --git https://github.com/1-3-7/disrobe disrobe-cli
# or, from a clone
cargo build --release              # about 4-6 minutes
./target/release/disrobe doctor    # optional: probe ~50 external tools
```

Optional external backends (Ghidra, CFR, jadx, ILSpy, de4dot) are off by default; every pass has an in-house default that runs without them. The slim build, the per-OS notes, and the split between build-time dependencies and the separate toolchains the graded numbers need are in the [installation guide](docs/src/installation.md) and [evidence/README.md](evidence/README.md).

## Quickstart

```sh
disrobe auto suspect.exe --out recovered/             # fingerprint, then chain the whole pipeline
disrobe identify suspect.exe                          # format, packer, and compiler ID
disrobe py decompile module.pyc --out src/            # recover Python source from bytecode
disrobe native unpack packed.exe --out unpacked.bin   # stub-emulator unpack, byte-recovery graded
```

`disrobe auto` fingerprints the input and composes the whole pipeline in one call: `PE -> UPX -> demangle`, `APK -> dex -> Java`, `PyInstaller -> PyArmor -> .pyc decompile`. With `--capture-stages` each stage lands in `out/01-*/`, `out/02-*/`, ..., `out/final/`. It always produces at least what the dedicated pass would, plus the cross-cutting recon, capability, string, and disassembly analysis.

Try it in your browser at [`1-3-7.github.io/disrobe/playground`](https://1-3-7.github.io/disrobe/playground/): the passes compile to WebAssembly and run client-side, and nothing is uploaded.

![demo](docs/src/demo/disrobe-demo.svg)

## Coverage

| Ecosystem | Tier | Headline measured figure | Oracle | Guide |
|---|---|---|---|---|
| Python bytecode | Recover | <!-- m:py_stdlib_pinned_pct -->96.6%<!-- /m --> per code object, 54.5% whole module | strong `[CI]` | [python](docs/src/languages/python.md) |
| PyArmor | Recover | <!-- m:pyarmor_frac -->72 / 72<!-- /m --> free-mode samples | strong `[CI]` | [python](docs/src/languages/python.md) |
| Python pickle | Recover | 340 / 340 re-execute equal | strong `[CI]` | [pickle](docs/src/languages/pickle.md) |
| JVM classfile | Recover | 131 / 131 methods recompile | recompile-only `[CI]` | [jvm](docs/src/languages/jvm-android.md) |
| Android DEX | Recover | 118 / 118 presentable classes | strong `[CI]` | [android](docs/src/languages/jvm-android.md) |
| .NET CIL | Recover | Eazfuscator VM and KoiVM lifted | strong `[CI]` | [dotnet](docs/src/languages/dotnet.md) |
| JavaScript, TypeScript | Recover | obfuscator.io, JS-Confuser, Jscrambler | pass-gated | [js](docs/src/languages/javascript.md) |
| WebAssembly | Recover | <!-- m:wasm_opcoverage_count -->133 of 133<!-- /m --> functions op-covered | strong `[CI]` | [wasm](docs/src/languages/wasm.md) |
| Native symbols, disasm, IR | Recover | DWARF, PDB, STABS, demangle, RTTI | pass-gated | [native](docs/src/languages/native.md) |
| Native decompile | Recover | C and Rust output re-executes equal | pass-gated | [decompile](docs/src/languages/native-decompile.md) |
| Native packers | Recover | UPX `.text` and `.pdata` byte-identical | strong `[CI]` | [unpack](docs/src/languages/native-unpack.md) |
| Native VM protectors | Detect-only | handler stream carved, not lifted | pass-gated | [unpack](docs/src/languages/native-unpack.md) |
| Go | Recover | <!-- m:go_typename_count -->838 of 838<!-- /m --> stripped type names | strong `[CI]` | [go](docs/src/languages/go.md) |
| Swift, Objective-C | Recover | 37 / 37 mangled symbols | strong `[CI]` | [swift](docs/src/languages/swift.md) |
| Lua | Recover | IronBrew2 devirt runs equal | strong `[CI]` | [lua](docs/src/languages/lua.md) |
| Ruby | Recover | greeter <!-- m:ruby_greeter_pct -->100%<!-- /m --> under MRI recompile | strong `[CI]` | [ruby](docs/src/languages/ruby.md) |
| PHP | Partial | eval-chain peel, Phar decode | pass-gated | [php](docs/src/languages/php.md) |
| BEAM | Recover | Core Erlang and Elixir `Dbgi` AST | pass-gated | [beam](docs/src/languages/beam.md) |
| AS3, Flash | Recover | ABC method-body source | pass-gated | [as3](docs/src/languages/as3.md) |
| Hermes, React Native | Recover | <!-- m:hermes_opcoverage_count -->8 of 8<!-- /m --> functions, no fallback ops | strong `[CI]` | [mobile](docs/src/languages/mobile.md) |
| Flutter Dart AOT | Partial | class and method attribution | pass-gated | [mobile](docs/src/languages/mobile.md) |
| Haxe HashLink | Recover | class names 100%, methods floor 75% | strong `[CI]` | [scriptlang](docs/src/languages/shell.md) |
| Shell, VBA, XLM | Recover | PowerShell, bash, batch, VBA, Excel 4.0 | pass-gated | [shell](docs/src/languages/shell.md) |
| Perl, R, Tcl | Partial | op-tree, `.rds` round-trip, starkit | pass-gated | [scriptlang](docs/src/languages/shell.md) |
| Nim, Zig, Crystal, D | Partial | demangle plus DWARF aggregates | pass-gated | [native](docs/src/languages/native.md) |
| Containers, firmware | Recover | <!-- m:containers_frac -->100 / 100<!-- /m --> formats write member bytes, self-counted | self-reported `[CI]` | [containers](docs/src/languages/containers.md) |
| Recon, secrets, format ID | Recover | 6 / 6 planted IOC categories | strong `[CI]` | [frisk](docs/src/frisk.md) |

A row's tier is the strongest level any family in that ecosystem reaches, not a promise for every family in it. **Recover** means real recovered output, source or bytes or structure, on the run path. **Partial** means a structural peel or constants only, with the residual stated. **Detect-only** means identification plus a stated reason the rest is not statically present, which is a legitimate triage result rather than a failure. Per-family tiers are in the linked guide and in `disrobe catalog [ecosystem]`, which prints the roster the binary itself carries. Breadth and depth are separate axes: `disrobe identify` and `disrobe catalog` span the full ecosystem list, while recovery depth per family runs from full source recovery down to detect-only.

Roster sizes the binary carries: Python source obfuscators (<!-- m:py_source_obfuscators -->20<!-- /m -->), JS bundlers (<!-- m:js_bundlers -->11<!-- /m -->), JVM and Android obfuscators (<!-- m:jvm_families -->10<!-- /m -->), .NET protectors (<!-- m:dotnet_protectors -->23<!-- /m -->), Packers (29 families), Lua (<!-- m:lua_catalog_entries -->16<!-- /m --> catalog entries), shell obfuscators (<!-- m:shell_families -->19<!-- /m -->), Android RASP (8 vendors).

Anti-analysis defeat, from opaque-predicate folding and control-flow deflattening through verified MBA simplification, stack-string emulation, calling-convention and type recovery, indirect-dispatch resolution, and generic VM devirtualization, is documented capability by capability with the gate behind each one in the [anti-analysis guide](docs/src/anti-analysis.md). Recursive payload peeling, the encoding and cipher set it reverses, and the structural check that stops a decode from advancing on garbage are in the [chain runner guide](docs/src/chain.md).

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

Read the first three Python rows together. A module counts as recovered only when every one of its code objects recompiles to equivalent bytecode. A module typically holds dozens of code objects, so a small per-object miss rate compounds into a large per-module one. To know whether a whole readable module comes back, use the whole-module figure of 54.5%, not the per-object 96.6%. That gap is the center of the evaluation rather than a footnote, and the [whitepaper](docs/src/architecture/whitepaper.md) works through it.

The Oracle column names the independent reference in a few words. What that reference is and how it can reject a wrong answer is in the cited test and in the linked guide.

| Metric | Measured | Oracle | Reproduce |
|---|---|---|---|
| Python `.pyc`, full 3.14 stdlib | <!-- m:py_stdlib_full_pct -->95.09%<!-- /m --> per code object `[local]` | recompile-equivalence | `crates/disrobe-pass-py-decompile/tests/harness/py_arbitrary_measure.py` |
| Python `.pyc`, pinned 200-module corpus | <!-- m:py_stdlib_pinned_pct -->96.6%<!-- /m --> per object, floor 96.60% `[CI]` | recompile-equivalence | `crates/disrobe-pass-py-decompile/tests/arbitrary_recompile_gate.rs` |
| Python `.pyc`, whole-module exact | 54.5% of modules recompile whole `[CI]` | recompile-equivalence | `crates/disrobe-pass-py-decompile/tests/arbitrary_recompile_gate.rs` |
| Python legacy 1.0-3.7 | <!-- m:py_legacy_count -->150 of 191<!-- /m --> gate-verified `[CI]` | recompile or token match | `crates/disrobe-pass-py-decompile/tests/legacy_recompile.rs` |
| PyArmor v6-v9-pro | <!-- m:pyarmor_frac -->72 / 72<!-- /m --> real-corpus samples `[CI]` | declared build match | `crates/disrobe-pass-pyarmor/tests/static_unpack_corpus.rs` |
| Pickle safety | 102 / 102 fixtures classify `[CI]` | pickletools semantics | `crates/disrobe-pass-pickle/tests/corpus.rs` |
| Pickle reconstruction roundtrip | 340 / 340 re-execute equal, floor 100% `[CI]` | CPython re-execution | `crates/disrobe-pass-pickle/tests/roundtrip.rs` |
| Android DEX, committed corpus | 118 / 118 presentable classes clean, 317 re-hosted bodies clean `[CI]` | real JVM verifier | `crates/disrobe-pass-jvm/tests/dalvik_verifier_gate.rs` |
| .NET Eazfuscator VM | 57 / 57 instructions lifted, ordered-CIL match `[CI]` | independent clean DLL | `crates/disrobe-pass-dotnet/tests/real_eazvm.rs` |
| .NET KoiVM | 6 / 6 bodies lifted, structural recovery >= 75% `[CI]` | independent clean build | `crates/disrobe-pass-dotnet/tests/real_koivm.rs` |
| .NET protectors | <!-- m:dotnet_protectors -->23<!-- /m --> classified, ConfuserEx2 decrypted `[CI]` | plaintext-absent check | `crates/disrobe-pass-dotnet/tests/confuserex2_full.rs` |
| WebAssembly, op-coverage | <!-- m:wasm_opcoverage_count -->133 of 133<!-- /m --> corpus functions `[CI]` | operator lowering | `crates/disrobe-pass-wasm-deob/tests/semantic_recovery_corpus.rs` |
| WebAssembly, execution-equiv | 57 / 57 eligible functions equal, 6 byte-identical `[CI]` | wasmtime differential | `crates/disrobe-pass-wasm-deob/tests/semantic_differential.rs` |
| WebAssembly obfuscator reversers | <!-- m:wasm_reversers -->4<!-- /m --> reverser families `[CI]` | parser and execution gates | `crates/disrobe-pass-wasm-deob/tests/obfuscators_e2e.rs` |
| Lua IronBrew2 2.7.0 devirt | runs equal, standard and MAX mode `[CI]` | real-`lua` differential | `crates/disrobe-pass-lua/tests/ironbrew2_real_oracle.rs` |
| Ruby YARV, greeter | <!-- m:ruby_greeter_pct -->100%<!-- /m --> `[CI]` | MRI recompile, opcode multiset | `crates/disrobe-pass-ruby/tests/yarv_recompile_oracle.rs` |
| Ruby YARV, megafile | floor <!-- m:ruby_megafile_pct -->98%<!-- /m --> `[CI]` | MRI recompile, opcode multiset | `crates/disrobe-pass-ruby/tests/yarv_recompile_oracle.rs` |
| Go type-name recovery | <!-- m:go_typename_count -->838 of 838<!-- /m --> type names, stripped `[CI]` | typelinks survive `-s -w` | `crates/disrobe-pass-go/tests/go_typemeta.rs` |
| Go BuildInfo and garble undo | BuildInfo recovered, `-literals` rebuilt `[CI]` | real toolchain output | `crates/disrobe-pass-go/tests/go_buildinfo_oracle.rs` |
| Swift symbol demangle | 37 / 37 mangled symbols `[CI]` | binary `LC_SYMTAB` symbols | `crates/disrobe-pass-swift-objc/tests/real_swift_demangle.rs` |
| HashLink (Haxe `.hl`) | class names 100%, method names floor 75% `[CI]` | names vs the original `.hx` | `crates/disrobe-pass-scriptlang/tests/real_hashlink_decompile.rs` |
| Native UPX | `.text` and `.pdata` byte-identical, floor 96% `[CI]` | byte-identity | `crates/disrobe-pass-native/tests/upx_unpack_all.rs` |
| Native packers, MPRESS | `.text` >= 90%, `.rdata` >= 85% `[CI]` | RVA-aligned recovery | `crates/disrobe-pass-native/tests/mpress_gauntlet.rs` |
| Native packers, Yoda's Crypter | `.rsrc`, `.text`, `.data` byte-identical `[CI]` | byte-identity | `crates/disrobe-pass-native/tests/packer_real_samples.rs` |
| Native packers, ASPack and PECompact | content and rebuilt IAT >= 98% byte-identical `[CI]` | RVA-aligned recovery | `crates/disrobe-pass-native/tests/aspack_pecompact_phase2.rs` |
| Native packers, MEW | structural loaded-image recovery `[CI]` | RVA-aligned recovery | `crates/disrobe-pass-native/tests/mew_unpack.rs` |
| Native packers, committed pairs | nspack 57721 / 60060, fsg 55263 / 60060, petite 86986 / 89648 `[CI]` | content-section bytes | `crates/disrobe-pass-native/tests/committed_packer_byte_recovery.rs` |
| Native packers, larger local samples | no figure published, samples uncommitted `[local]` | whole-image comparison | `crates/disrobe-pass-native/tests/petite_unpack.rs` |
| Native packers, kkrunchy | kkrunchy and kkrunchy classic payloads `[CI]` | payload byte-identity | `crates/disrobe-pass-native/tests/kkrunchy_unpack.rs` |
| Native stub-emulator unpack | dispatch and decode round-trip `[CI]` | stub-emu equivalence | `crates/disrobe-pass-native/tests/stub_pack_oracle_roundtrip.rs` |
| Hermes HBC v96 | <!-- m:hermes_opcoverage_count -->8 of 8<!-- /m --> functions, 0 fallback `[CI]` | op-coverage, source bodies | `crates/disrobe-pass-mobile/tests/real_hermes_sample.rs` |
| Hermes production bundle | <!-- m:hermes_functions -->122,633<!-- /m -->-function parse `[local]` | parse scale, gitignored input | `crates/disrobe-pass-mobile/tests/real_hermes_discord.rs` |
| APK secrets vs apkleaks | 8 / 8 planted secrets vs 5 / 8 `[CI]` | planted ground truth | `cargo run -p disrobe-bench-head-to-head` |
| frisk IOC detection | 6 / 6 planted IOC categories `[CI]` | planted ground truth | `crates/disrobe-core/tests/frisk_gauntlet.rs` |
| Container / archive / firmware extraction | <!-- m:containers_frac -->100 / 100<!-- /m --> formats in-tree `[CI]` | in-tree extraction count | `crates/disrobe-binfmt/src/container.rs` |
| Cross-platform determinism | 3 / 3 real fixtures byte-identical, 3-OS matrix `[CI]` | BLAKE3 hash equality | `crates/disrobe-cli/tests/determinism_cross_platform.rs` |

The Python figures count code objects, not modules. The full-stdlib row covers <!-- m:py_stdlib_full_count -->17378 of 18276<!-- /m --> objects across <!-- m:py_stdlib_full_modules -->574<!-- /m --> modules; the pinned row covers <!-- m:py_stdlib_pinned_count -->6072 of 6286<!-- /m --> objects across <!-- m:py_stdlib_pinned_modules -->200<!-- /m --> modules, and the same legacy gate reaches <!-- m:py_legacy_local_count -->166 of 191<!-- /m --> locally. The Go row is measured on a stripped go1.26.3 fixture, its gate pins the count and holds the ratio above a <!-- m:go_typename_pct -->85%<!-- /m --> floor, and `go_garble_undo.rs` covers the garble leg beside it.

The Android committed-corpus row is measured on small methods; 37 of 155 classes are link-skipped and ungraded, and the real-apk row further down carries the production scale. The WebAssembly op-coverage figure is 100% of the 38 parseable modules, and the other 2 of the 40 corpus files are skipped on wat-parse or signature-extraction failure, with the gate pinning both counts. The .NET Eazfuscator row has a second leg, `[local]`, in which the recovered CIL re-injects to byte-identical stdout; it needs a .NET runtime that CI does not provision.

The Swift row is pinned against a committed fixture's own symbol table; the parity leg against the reference `swift-demangle` runs only where that tool is installed, which CI does not provide. HashLink also parses the whole HLB image byte-exact, 336 functions and 421 types on the committed fixture. The PyArmor row draws its samples from a corpus of 289 committed files. The container row's assertion is `every_real_format_extracts_in_tree`. The six planted IOC categories frisk is graded on are endpoints, manifest findings, URLs, IPv4, email, and `.onion`.

Native UPX recovers about 96% of the whole image beyond the two byte-identical sections. For the committed packer pairs, `.text` and `.data` are byte-identical for all three families and nspack's `.rdata` is byte-identical too, and one packed-and-original pair per family is committed, so each figure reproduces from a clean checkout. The same decoders score lower on the whole-image measure over larger uncommitted vendor samples, with the content sections holding up far better than the whole image; `fsg_unpack.rs` and `nspack_byte_recovery.rs` sit beside the cited petite test, and no figure is published for any of them because nothing there reproduces or is pinned. Determinism is also checked across worker-pool sizes: the same fixtures run through `disrobe auto <dir>`'s batch runner at `--jobs 1` and `--jobs 4` produce identical bytes, and that batch runner is the one real concurrent code path in the CLI.

### Recompile-only

| Metric | Measured | Oracle | Reproduce |
|---|---|---|---|
| JVM classfile `recompile-only` | 131 / 131 methods recompile error-free, floor 131 `[CI]` | real `javac`, JDK 25 | `crates/disrobe-pass-jvm/tests/decompile_recompile_rate.rs` |

Nothing asserts bytecode-equivalence for that row. The recovered source compiles, which is a weaker statement than the Strong tier makes.

### Self-reported coverage

| Metric | Measured | Oracle | Reproduce |
|---|---|---|---|
| Android DEX, real APKs `coverage-self-reported` | <!-- m:dalvik_body_pct -->92.5%<!-- /m --> of defined methods `[local]` | self-reported, gitignored apks | `crates/disrobe-pass-jvm/tests/dex2jar_realworld_apks.rs` |
| Android DEX, real APKs, count `coverage-self-reported` | <!-- m:dalvik_body_frac -->82788 / 89516<!-- /m --> `[local]` | self-reported, gitignored apks | `crates/disrobe-pass-jvm/tests/dalvik_realworld_body_attest.rs` |

That figure is the total across all three apks and not any one of them. The per-apk split, and a separate verifier-attested population with its own smaller denominator, are in the [Android guide](docs/src/languages/jvm-android.md).

The recovered bodies that can be presented to the verifier are attested at <!-- m:dalvik_body_attested_frac -->2960 of 2994<!-- /m -->, graded by real `java -Xverify:all` over bodies rather than methods, which is a different and smaller population than the method-coverage figure above.

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
cargo run  -p disrobe-bench-native-unpack                                 # native packer byte-recovery table
```

[evidence/README.md](evidence/README.md) documents the build/runtime dependency boundary and the offline-vs-network reproducibility tiers.

</details>

## Head-to-head

![Python decompilation coverage by version against competing tools](docs/assets/python-versions.svg)

Most tools specialize in one layer. `disrobe` chains unpacking, bytecode and native recovery, recon, and verification in one static binary. Only committed input, pinned tools, a shared oracle, and a drift gate go in the table below. The runner is [`benches/head-to-head/`](benches/head-to-head/); pinned tools live in [`evidence/competitors/`](evidence/competitors/).

| Surface | `disrobe` | Leading tool | Result | Reproduce |
|---|---|---|---|---|
| JVM classfile | 131 / 131 methods recompile | CFR 0.152: 105 / 106 | `disrobe` leads on clean methods and clean rate | `cargo run -p disrobe-bench-head-to-head` |
| Android DEX | 129 / 132 methods recompile | JADX 1.5.5: 128 / 130 | mixed: `disrobe` emits one more clean method; JADX has the higher clean rate | `cargo run -p disrobe-bench-head-to-head` |
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

Two things look like walls but are not. PyArmor BCC/super-mode bodies and Nuitka/Nim/Zig/Crystal native bodies are compiled machine code, present in the artifact rather than absent, so `disrobe` carves them and lifts them to pseudo-C or pseudo-Rust with its in-house x86-64 decompiler. This carve path lifts each body on its own, without the cross-function call resolution `--backend native` applies when it walks a whole object. For PyArmor BCC it also links each compiled function back to its source module, qualified name, class, and arity, so you get a function-to-source map and a reconstructed `.py` skeleton; straight-line and guarded-conditional bodies reconstruct to runnable Python verified against CPython, while loops degrade to the skeleton. The surrounding metadata, symbols, and names still recover fully.

Bytecode-to-source is structurally faithful but never byte-identical: `.class`, `.dex`, and CIL erase local names, generics, comments, and exact formatting. On large, deeply nested native binaries Ghidra and IDA still lead, so `disrobe` unpacks, recovers symbols, and exports straight into them (`native export --format ghidra|ida|json`) and can drive ghidra-headless itself (`native decompile --backend ghidra`) rather than competing on that surface.

## CLI surface

Every pass is a subcommand. One representative command per family:

```sh
disrobe auto sample.bin --out recovered/ --capture-stages   # detect and chain, keeping every stage
disrobe catalog native                                      # supported families and recovery tier
disrobe py decompile module.pyc --out src/                  # CPython 1.0-3.15
disrobe pyarmor unpack protected.py --out out/              # static unpack
disrobe js unbundle app.bundle.js --out src/                # un-webpack, source-map reconstruction
disrobe wasm decompile module.wasm --target rust            # also ts, wat, c
disrobe jvm decompile app.apk --out src/                    # in-house Dalvik decompiler is the default
disrobe dotnet decompile App.dll --out src/                 # in-house CIL to C#/F#/VB
disrobe native unpack packed.exe --out unpacked.bin         # in-house decoders plus x86 stub emulator
disrobe native decompile app.exe --backend native           # x86-64/AArch64 to C, --format rust for Rust
disrobe native disasm stripped.bin --emit cfg-dot           # function discovery plus per-function CFG
disrobe native export packed.exe --format ghidra            # rebuilt PE plus a Ghidra/IDA/JSON symbol map
disrobe query packed.exe string-decoders                    # queryable IR over stripped code
disrobe capabilities packed.exe                             # MITRE ATT&CK and MBC with per-match evidence
disrobe taint malware.exe --source recv --sink system       # source-to-sink dataflow over the shared IR
disrobe go recover app --out symbols.json                   # pclntab symbols, BuildInfo, garble undo
disrobe lua decompile script.luac --out script.lua          # 5.1-5.4, LuaJIT, Luau, IronBrew2 devirt
disrobe shell deob payload.ps1 --out clean.ps1              # PowerShell, bash, batch, VBA, Excel 4.0
disrobe extract firmware.bin --out carved/ --recursive      # carve every supported container format
disrobe frisk recovered/ --format sarif                     # secrets, endpoints, buckets, IOCs
disrobe prowl example.com --subs --format json              # the one command that touches the network
disrobe report out/ --format html                           # self-contained offline forensic report
```

The complete surface, flag by flag, is in the [command reference](docs/src/cli/reference.md); the flags that apply everywhere are in [global flags](docs/src/cli/global-flags.md). `disrobe passes` lists the passes, `disrobe catalog [ecosystem]` lists every recognized family and its tier, and `disrobe explain <code>` looks up any `DR-` diagnostic with its cause and fix.

## Library, bindings, and daemon

The CLI is a thin layer over the same crates, so a TUI, an IDE plugin, a web service, or a batch engine drives the full pass set directly. Each pass is its own Rust crate over shared `disrobe-core` and `disrobe-ir` types. `import disrobe` gives a pyo3 `abi3` module for Python 3.9+, shipping `.pyi` and `py.typed`, bytes in and typed report objects out, never touching the filesystem. `disrobe serve` speaks HTTP, gRPC, and LSP, and `disrobe serve --mcp` exposes the same operations as Model Context Protocol tools. Signed WebAssembly Component plugins verify and execute under the sandbox as a library capability; the CLI does not yet dispatch an analysis pass through one.

See the [library guide](docs/src/library.md), the [Python bindings](docs/src/python-bindings.md), and [the daemon](docs/src/cli/serve.md).

## Architecture

![Chain runner stages from raw bytes through the IR ladder to verified source](docs/assets/ir-ladder.svg)

![End-to-end recovery chains from packed, mobile, and frozen inputs to oracle-verified source](docs/assets/architecture.svg)

`disrobe` is a chain runner over single-purpose passes that lower every artifact onto one shared intermediate-representation ladder. Detection fingerprints the input, the chain runner recursively unpacks and routes it, and each pass recovers what is statically present and reports the rest with a measured score.

```text
   Raw  -->  Disasm  -->  MIR  -->  HIR  -->  Surface
   bytes     opcodes      mid       high      source
```

Unpacking and decryption operate at Raw, where byte-exact recovery lives. Disassembly produces Disasm. Decompilers do their structural work at MIR and HIR, then render Surface, which is recompiled and verified against the oracle. Ten lifter paths feed the ladder: nine bytecode front-ends in `disrobe-nir-lift` (AVM2, BEAM, CIL, Dalvik, JVM, Lua, Python, WebAssembly, YARV) plus native via the disassembler. Three more consumers sit on the same normalized Mir: `disrobe query` and `disrobe capabilities`, `disrobe taint`, and `disrobe-semdiff`, which matches functions by a relocation-invariant signature so two builds of the same source diff to nothing while a single changed function is reported.

Every recovered artifact is persisted as a `.dr` envelope: an rkyv payload, a postcard metadata sidecar, and a BLAKE3 root over both. Identical input yields a byte-identical envelope, so cache hits and fresh runs are indistinguishable, and any result can be transcoded, diffed, signed, or replayed. Any pass can emit an `--llm` metadata sidecar carrying the call graph, types, control flow, capability surface, and provenance.

The [architecture guide](https://1-3-7.github.io/disrobe/latest/architecture.html) has the full model, the [IR ladder page](docs/src/ir-ladder.md) the rung definitions, and the [whitepaper](https://1-3-7.github.io/disrobe/latest/architecture/whitepaper.html) the deterministic CPython decompiler, the typed-AST x86-64 lift, managed-VM devirtualization, and the grading discipline behind every claim.

## Safety posture

Every default path is pure static analysis and never executes the sample. The pickle suite is symbolic and never unpickles. The only code-execution paths, the PyArmor v6/v7 dynamic hook and the BCC native lift, sit behind explicit `--allow-dynamic` and `--allow-bcc` flags with a watchdog; run those inside a sandbox. The parsing surface is hardened against malformed and oversized input. See [Forensics and malware-safety posture](https://1-3-7.github.io/disrobe/latest/forensics-safety.html) and the [threat model](https://1-3-7.github.io/disrobe/latest/threat-model.html).

## Documentation

Full docs site: [`1-3-7.github.io/disrobe`](https://1-3-7.github.io/disrobe/), covering the architecture, the IR ladder, the chain runner, per-language guides, the Python-bindings reference, the complete CLI reference, and the safety posture. The book source is under [`docs/`](docs/). [Per-protector stances](https://1-3-7.github.io/disrobe/latest/legal.html#per-protector-stances-on-file) records the legal posture behind a grey-zone recognizer escalating to a full peel.

Integrations: a [GitHub Action](docs/src/integrations/github-action.md) that scans a path or glob and uploads SARIF to code scanning, a [pre-commit hook](docs/src/integrations/pre-commit.md) that blocks a commit on a packed or obfuscated artifact, an [MCP server](docs/src/integrations/mcp.md), and [editor plugins](docs/src/integrations/editor-plugins.md) for VS Code, IDA Pro, Ghidra, and Binary Ninja.

## Legal

Decompilation for security research, interoperability, and recovery of your own source is permitted in most jurisdictions (17 U.S.C. section 1201(f), Directive 2009/24/EC Art. 6, CDPA 1988 ss. 50B-50BA, and equivalents in CA/AU/JP). The full posture with statutory citations and a takedown channel is in [LEGAL.md](LEGAL.md). Legally sensitive recovery paths that need an explicit authorization assertion expose `--i-have-authorization` and refuse without it.

## Contributing

Contributions are welcome; see the [contributing guide](.github/CONTRIBUTING.md). For security issues, open a [private advisory](https://github.com/1-3-7/disrobe/security/advisories/new) rather than a public issue. See [SECURITY.md](SECURITY.md).

## License

[Elastic License 2.0](LICENSE), source-available. Companies and security researchers may use, copy, modify, and distribute `disrobe` for free; attribution is mandatory, so keep the author, copyright, and licensing notices intact. You may not provide `disrobe` to third parties as a hosted or managed service, and you may not remove or obscure any licensing, copyright, or other notices. The `disrobe` name and marks are reserved and granted no rights by the license. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
