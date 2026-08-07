# Supported families catalog

This is the authoritative per-ecosystem list of every packer, obfuscator, protector, freezer, and bundler `disrobe` recognizes, with the support tier for each. The live CLI view is `disrobe catalog [ecosystem]`; a default build, which turns the `full` feature on, reports <!-- m:catalog_family_total -->169<!-- /m --> families across <!-- m:catalog_ecosystems -->15<!-- /m --> ecosystems, and the totals on this page are the `full` ones. Most catalogs sit behind a cargo feature, so a build with features trimmed registers fewer catalogs and reports a smaller total.

`cargo run -p xtask -- regen --check` re-derives the headline total, the native tier split, and the per-pass counts in the tables below from the tables the binary itself carries (`Packer` in `crates/disrobe-pass-native/src/packers/mod.rs`, `CATALOG_COUNT` in each pass `chain_detector.rs`, `Protector::ALL` in `crates/disrobe-pass-dotnet/src/protectors.rs`, and `RaspVendor` in `crates/disrobe-pass-jvm/src/rasp.rs`), so a family added to the binary without this page moving with it fails that check. Three rows count something no catalog table holds, `Freezers / packagers`, `Freezers / packagers (experimental, unvalidated)`, and `JS bundlers (unbundler)`; for those the check compares the published count against the family list beside it, which keeps the two halves of a row consistent but proves neither against the binary.

```sh
disrobe catalog
disrobe catalog native
disrobe catalog python --json
```

Three words describe how far recovery goes for a family, the same three the README uses:

- **Recover**: real recovered output (source, bytes, or structure), measured against an independent oracle where one exists.
- **Partial**: the layer is identified and what is intact is extracted or peeled, with the residual stated.
- **Detect-only**: identification plus a stated reason the rest cannot be recovered statically.

A **wall** is the strongest case of detect-only: the data is not in the artifact at all, so no static tool recovers it without the runtime key, the live process, or the network-fetched payload. Every wall is detect-only, and detect-only also covers families that are identified but reported without static recovery. Detect-only is a useful triage result and not a failed analysis: see [refusal is a result](./introduction.md#refusal-is-a-result) for why, and [reading a result](./reading-a-result.md) for what to do with one.

`disrobe catalog` prints the same three tiers with the `SupportQuality` labels the binary carries (`crates/disrobe-core/src/chain/obfuscator_catalog.rs`), where `full` is the Recover tier: `[full]`, `[partial]`, `[detect-only]`.

The `disrobe auto` chain at the bottom is what stitches these together: it fingerprints the input, runs the matching pass, re-fingerprints the output, and repeats until nothing else applies.

## Native packers and protectors (29)

The `Packer` enum carries <!-- m:native_packer_variants -->29<!-- /m --> variants across five `UnpackerStatus` tiers (<!-- m:native_tier_implemented -->12<!-- /m --> + <!-- m:native_tier_stub_eval_pending -->6<!-- /m --> + <!-- m:native_tier_grey_carve -->3<!-- /m --> + <!-- m:native_tier_grey_detect_only -->6<!-- /m --> + <!-- m:native_tier_delegated -->2<!-- /m --> = <!-- m:native_packer_variants -->29<!-- /m -->). The native chain detector catalog advertises <!-- m:native_catalog_entries -->27<!-- /m --> of them; the two CLR-layer crypters route to the .NET pass, so `disrobe catalog native` lists <!-- m:native_catalog_entries -->27<!-- /m -->.

The tier names below are the in-tree `UnpackerStatus` values, so the split is exactly what the binary advertises. `crates/disrobe-pass-native/src/packers/mod.rs` test `published_tier_counts_match_this_enum` asserts every count in the table below against `unpacker_status`, so a variant cannot be added or moved between tiers without this page failing. The family names in each row are written by `cargo run -p xtask -- regen` from the same enum, and `regen --check` fails when a row names a family the binary does not carry, omits one it does, or files one under the wrong tier. Only the Implemented tier reaches an unpack routine, and the same check fails when a family in that row has no dispatch arm in `crates/disrobe-pass-native/src/chain_detector.rs` or when a family outside it has one.

| Tier (`UnpackerStatus`) | Count | Families |
|---|---|---|
| **Implemented**: byte-exact decoders plus an in-house x86 stub emulator | <!-- m:native_tier_implemented -->12<!-- /m --> | <!-- packer-roster:implemented -->Donut, sRDI, UPX, ASPack, Petite, MPRESS, FSG, PECompact, Yoda's Crypter, NSPack, MEW, kkrunchy<!-- /packer-roster --> |
| **StubEvalPending**: stub emulator validated against a spec-built stub, real-sample recovery tracked | <!-- m:native_tier_stub_eval_pending -->6<!-- /m --> | <!-- packer-roster:stub-eval-pending -->ASProtect, Morphine, nPack, NeoLite, PolyCryptor, Warzone Crypter<!-- /packer-roster --> |
| **GreyZoneDetectAndCarve**: virtualizing tier, runtime-keyed handler stream | <!-- m:native_tier_grey_carve -->3<!-- /m --> | <!-- packer-roster:grey-zone-detect-and-carve -->Yoda's Protector, VMProtect, Themida / WinLicense<!-- /packer-roster --> |
| **GreyZoneDetectOnly**: commercial protector tier, reported without static recovery | <!-- m:native_tier_grey_detect_only -->6<!-- /m --> | <!-- packer-roster:grey-zone-detect-only -->PE-Protector, PELock, Enigma Protector, Armadillo, Obsidium, WinLicense<!-- /packer-roster --> |
| **DelegatedToDotnet**: managed CLR crypter, recovery delegated to the .NET pass | <!-- m:native_tier_delegated -->2<!-- /m --> | <!-- packer-roster:delegated-to-dotnet -->DotNetPatcher, NetCryptor<!-- /packer-roster --> |

Donut and sRDI are shellcode loaders, so what the Implemented tier recovers for them is the embedded payload rather than a decompressed image.

The recover tier is scored byte-for-byte against real committed originals: UPX `.text` and `.pdata` are bit-identical (the whole loaded image about 96%, the residual being loader-rebuilt relocations and IAT the OS resolves at run time), ASPack and PECompact rebuild the decompressed image with the reconstructed IAT at least 98% byte-identical, and Yoda's Crypter `.rsrc` is byte-identical with its `.text` decrypted to full plaintext. NSPack, FSG and Petite each reproduce from a clean checkout with one committed packed-and-original pair apiece. For the NSPack pair the gate holds the whole loaded image at or above 94.1% and the `.text`, `.rdata` and `.data` span at or above 99.3%. A per-section gate scores those three decoders over a wider span that also counts `.rsrc`: NSPack 57721 of 60060 bytes, FSG 55263 of 60060, and Petite 86986 of 89648. `.text` and `.data` are byte-identical for all three, and NSPack's `.rdata` is byte-identical as well, because its import lookup and address tables are rebuilt from the module record the stub carries rather than left for the loader. Their shared residual is the resource directory, now recovering 2333 of 4672 bytes for NSPack and 1552 of 4672 for FSG once the original tree is placed at its own RVA, and relocations are scored separately as loader-rebuilt. Larger local-only samples score lower on the whole-image measure, and no figure is published for them because those samples are not committed and nothing pins them, so the numbers above describe the committed pairs rather than the families. kkrunchy is byte-exact against committed fixtures and does reproduce. The full breakdown is in the [native guide](./languages/native.md).

## Python

| Surface | Count | Families |
|---|---|---|
| **Freezers / packagers** | 8 | PyInstaller 2.x-6.20+, Nuitka (onefile / standalone / module / wheel), cx_Freeze, py2exe, shiv, pex, Briefcase, SourceDefender `.pye` |
| **Freezers / packagers (experimental, unvalidated)** | 1 | PyOxidizer (experimental, unvalidated) |
| **Protector (PyArmor)** | <!-- m:pyarmor_catalog_versions -->7<!-- /m --> versions | PyArmor v6-v9-pro modes are cataloged and routed. Separately, the <!-- m:pyarmor_frac -->72 / 72<!-- /m --> manifest-named v8/v9 default-trial wrappers decrypt and decode one complete header-anchored root `CodeObject`. This self-reported structural result does not cover v6/v7, other v8/v9 wrapper populations, registered-license/pro, BCC, or super mode. The v3-v5 RSA-wrapped-key tier is a runtime-key wall. |
| **Source obfuscators (AST-evaluator)** | <!-- m:py_source_obfuscators -->20<!-- /m --> | Kramer/Specter, Berserker, Jawbreaker, BlankOBF, PlusOBF, Wodx, pyobfuscate.com, pyobfuscate.com (2026 XOR/lambda), PyObfuscator (mauricelambert), python-obfuscator (PyPI), ObfuXtreme, Manglify, Oxyry, pyminifier, online-obfuscator family, Xindex, pyobfus, Pypacker, Patchwork, pyc-zipper |

Jawbreaker's b16/b32/b64 loader shell is decoded statically, but a payload it fetches from a remote paste at run time is absent from the file. ObfuXtreme's AES-CBC/b85/xor static body is recovered; its runtime-payload segment is not in the artifact. python-obfuscator (PyPI), pyobfus, and Pypacker are detect plus partial-peel. Compiled Cython extensions (`.pyd` / `.so`) have their Python-visible surface (function and class names, docstrings, signatures) recovered from the module's symbol tables, with a structural fallback when the binary is stripped. See the [Python guide](./languages/python.md).

## JavaScript / TypeScript / WebAssembly

| Surface | Count | Families |
|---|---|---|
| **JS chain catalog** | <!-- m:js_catalog_entries -->10<!-- /m --> | 4 obfuscators (obfuscator.io full pipeline, JS-Confuser, Jscrambler, js-obfuscator (jsobfu)) plus 6 bundler markers (webpack, Vite, Rollup, esbuild, Turbopack, Bun) |
| **JS esoteric encoders + protectors** | separate detectors | JSFuck, aaencode, jjencode, JSFiretruck, Dean Edwards Packer (decoded); JSDefender and Arxan / Digital.ai (detect + static-transform peel); PACE (detect-only) |
| **JS bundlers (unbundler)** | <!-- m:js_bundlers -->11<!-- /m --> | webpack 4, webpack 5, Vite, Rollup, Rolldown, esbuild, Turbopack, Bun, Parcel, Browserify, SystemJS |
| **WASM obfuscators** | <!-- m:wasm_catalog_entries -->5<!-- /m --> (catalog) | Jscrambler-WASM, Wobfuscator, Tigress-via-Emscripten, Wasmixer (3 with transforms undone on modelled output, no artifact from the tools themselves is committed); Tigress-via-Emscripten and wasm-name-obfuscator are detect + classify only because the Tigress dispatcher and name helpers are not on the `wasm deob` run path, and wasm-name-obfuscator's hex renames destroy the original names |

The [JS](./languages/javascript.md) and [WebAssembly](./languages/wasm.md) guides cover each pipeline.

## JVM / Android / .NET

| Surface | Count | Families |
|---|---|---|
| **JVM / Android protectors** | <!-- m:jvm_families -->10<!-- /m --> | ProGuard/R8 (mapping replay), Zelix KlassMaster, Allatori, Stringer, DashO, DexGuard (detect + structural peel, with in-class string-decrypt emulation for the keyed-constant variants), BlackObfuscator (DEX deflattening); yGuard, SkidSuite2, JBCO (detect-only) |
| **Android RASP vendors** | <!-- m:rasp_vendors -->8<!-- /m --> | Promon SHIELD, Guardsquare DexGuard RASP, Guardsquare ThreatCast, Appdome, OneSpan, Arxan / Digital.ai, Zimperium zShield, Licel DexProtector |
| **.NET protectors** | <!-- m:dotnet_protectors -->23<!-- /m --> | ConfuserEx, ConfuserEx2, Dotfuscator, Dotfuscator CE, SmartAssembly, Babel, DeepSea, Spices.Net, Goliath, Skater, .NET Reactor, Eazfuscator.NET, CryptoObfuscator, ArmDot, Agile.NET, Obfuscar, Themida (.NET wrapper), ILProtector, MaxToCode, KoiVM, DotNetPatcher, NetCryptor, BitMono |

On .NET, ConfuserEx2 constant decryption is reversed on a real committed sample, the Eazfuscator VM tier is devirtualized at 57 of 57 instructions against an in-repo EazVM virtualizer of our own, and the KoiVM VM tier is devirtualized on a sample produced by the real KoiVM tool (6 of 6 bodies lifted to CIL). ILProtector, MaxToCode, and the Themida/.NET wrapper derive their per-method key in a native loader absent from the artifact, so those bodies are runtime-key walled. See the [JVM and Android](./languages/jvm-android.md) and [.NET](./languages/dotnet.md) guides.

Detection covers every family in that row. String decryption is a narrower claim and it rests on different evidence per family. It is graded against a committed assembly the protector's own tool produced for <!-- dotnet-string-evidence:real-sample -->ConfuserEx2, Obfuscar, BitMono<!-- /dotnet-string-evidence -->. For <!-- dotnet-string-evidence:modelled-algorithm -->SmartAssembly, Spices.Net, Skater, .NET Reactor, Eazfuscator.NET, CryptoObfuscator<!-- /dotnet-string-evidence --> the decoder implements the published algorithm and is graded against a fixture built to that algorithm; no assembly produced by those products is committed, so each of those families is detected and its decryption modelled, not confirmed against a real protected assembly. String recovery stops at detection for <!-- dotnet-string-evidence:runtime-keyed -->Themida (.NET wrapper), ILProtector, MaxToCode<!-- /dotnet-string-evidence -->, whose keys live in a native loader the artifact does not carry.

## Lua

The Lua chain catalog is <!-- m:lua_catalog_entries -->16<!-- /m --> entries: <!-- m:lua_catalog_obfuscators -->14<!-- /m --> obfuscator families plus the Luau and GLua dialect detectors.

| Surface | Count | Families |
|---|---|---|
| **Obfuscators** | <!-- m:lua_catalog_obfuscators -->14<!-- /m --> | IronBrew2 (full VM devirtualization), Prometheus, MoonSec V1, MoonSec V2, MoonSec V3, AztupBrew, DarkSec, Boronide, PSU, WeAreDevs, luaobfuscator.com, SLua, Hercules, Luraph |
| **Dialect detectors** | <!-- m:lua_catalog_dialects -->2<!-- /m --> | Luau bytecode, Garry's Mod Lua (GLua) |

IronBrew2 2.7.0 is reversed on real committed output in standard and MAX mode, validated by a real-`lua` execution differential. MoonSec-shape recovery runs against a synthetic bootstrap of our own design pending a real sample. The [Lua guide](./languages/lua.md) walks the devirtualizer.

## Shell

| Surface | Count | Families |
|---|---|---|
| **Shell obfuscators** | <!-- m:shell_families -->19<!-- /m --> | PowerShell Invoke-Obfuscation (Token, AST, String, Encoding, Compress, Launcher), Invoke-Stealth, PowerHell, Chameleon, psobf, ISESteroids; Bashfuscator (Token, String, Obfuscate, Compress), bash IFS/eval indirection, and node-bash-obfuscate; Batch `%random%` and set-indirection |

Full VBA p-code decompile (264-opcode table, VBA3/5/6/7) with VBA-stomping detection rounds out the shell pass, alongside Excel 4.0 (XLM) macro-formula recovery (BIFF8/BIFF12 Ptg decode, shared-formula and `Auto_Open` resolution) and PDF maldoc analysis (embedded JavaScript, launch and embedded-file actions, both xref forms, RC4/AESV2 empty-password decrypt). See the [shell guide](./languages/shell.md).

## PHP

| Surface | Count | Families |
|---|---|---|
| **Commercial encoders** | <!-- m:php_catalog_entries -->3<!-- /m --> (catalog) | ionCube, SourceGuardian, Zend Guard: envelope detect and wall (the decrypt key is native-loader-resident), with a partial `op_array` skeleton for the legacy statically-keyed cases |

Stacked eval-chain obfuscation (FOPO, Better PHP Obfuscator, and the base64/gzinflate/rot13/XOR layer set) and Phar archives are peeled and walked in the same pass. See the [PHP guide](./languages/php.md).

## Other runtimes

| Ecosystem | Coverage |
|---|---|
| **Go** | garble report graded None / Detected / Partial / Full; `garble -literals` simple and full-key literals recovered through static blob pairing plus bounded x86-64 thunk/inline emulation. Type names resolved above an <!-- m:go_typename_pct -->85%<!-- /m --> floor on the committed go1.26.3 fixture. |
| **Ruby** | MRI/YARV 2.6-3.4 and mruby recompile-equivalence decompile; Ruby2Exe and Ocra freezers detected; JRuby and TruffleRuby AOT classified. |
| **BEAM** | `.beam` and `.ez` chunk parse, Core Erlang lift, Elixir `Dbgi` quoted-AST recovery. |
| **Swift / Obj-C** | Mach-O class-dump plus SwiftShield mapping parser and explicit-key single-byte XOR blob decoding; `objc_msgSend` call sites in recovered native bodies resolved to selector and receiver class. |
| **ActionScript 3** | SWF parse and AVM2 disasm; commercial obfuscators (secureSWF, DoSWF, Kindi, Irrfuscator, swfLock) detect-only. |
| **Hermes / Flutter** | Hermes bytecode v60-v96 header parse, v76/v84/v96 lift against a real hermesc sample; Flutter Dart kernel byte-exact body recovery and ARM64 AOT disasm, graded against a self-authored Dart 3.12.2 android-arm64 product-mode corpus and, measured locally, a real RustDesk 1.4.9 `libapp.so` fetched by pinned hash. |
| **Containers / archives / filesystems / firmware** | <!-- m:containers_formats -->100<!-- /m --> formats detected, all <!-- m:containers_formats -->100<!-- /m --> carrying an in-tree extractor. <!-- roster-breadth:containers-exercised -->34<!-- /roster-breadth --> of them are driven to member bytes by an input this repository commits; the remainder are declared rather than measured. |

## The `disrobe auto` chain

`disrobe auto` is the front door to the whole catalog. It fingerprints the input, picks the highest-confidence pass, runs it, re-fingerprints the output, and repeats until no further pass clears the confidence threshold or the depth cap is hit. Detection spans 23 pass crates.

```sh
disrobe auto suspect.exe --out recovered/                 # detect + chain the whole pipeline
disrobe auto suspect.exe --out recovered/ --capture-stages # keep each stage's byte-exact output
disrobe auto firmware-dir/ --out out/ --batch-max-depth 6
```

Representative chains:

- `PE -> UPX -> rust-demangle`
- `PyInstaller -> PyArmor -> .pyc decompile`
- `APK -> dex -> Java + manifest`
- `Electron .asar -> unbundle -> source`
- `ConfuserEx2 PE -> de4dot -> ILSpy -> C#`

With `--capture-stages`, stage outputs land in `out/01-*/`, `out/02-*/`, ..., `out/final/`. The full mechanism, including the depth cap, cycle detection, and the `chain.json` topology descriptor, is in [The chain runner](./chain.md).
