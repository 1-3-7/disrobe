# Supported families catalog

This is the authoritative per-ecosystem list of every packer, obfuscator, protector, freezer, and bundler `disrobe` recognizes, with the support tier for each. The live CLI view is `disrobe catalog [ecosystem]`; the current binary reports 167 families across 15 ecosystems. The counts come from the in-tree catalog tables (`Packer` in `crates/disrobe-pass-native/src/packers/mod.rs`, each pass `chain_detector.rs` `CATALOG_COUNT`, `crates/disrobe-pass-dotnet/src/protectors.rs`, `crates/disrobe-pass-jvm/src/protectors.rs` and `rasp.rs`), so they match the binary, not a hand-kept list.

```sh
disrobe catalog
disrobe catalog native
disrobe catalog python --json
```

Three words describe how far recovery goes, the same vocabulary the README uses:

- **Recover**: real recovered output (source, bytes, or structure), measured against an independent oracle where one exists.
- **Detect + carve**: the layer is identified and any intact parts are extracted, without full reversal.
- **Wall**: no static tool can recover it without the runtime key, the live process, or the network-fetched payload.

The `disrobe auto` chain at the bottom is what stitches these together: it fingerprints the input, runs the matching pass, re-fingerprints the output, and repeats until nothing else applies.

## Native packers and protectors (27)

The `Packer` enum carries 27 variants across five `UnpackerStatus` tiers (10 + 6 + 3 + 6 + 2 = 27). The native chain detector catalog advertises 25 of them; the two CLR-layer crypters route to the .NET pass, so `disrobe catalog native` lists 25.

The tier names below are the in-tree `UnpackerStatus` values, so the split is exactly what the binary advertises.

| Tier (`UnpackerStatus`) | Count | Families |
|---|---|---|
| **Implemented**: byte-exact decoders plus an in-house x86 stub emulator | 10 | UPX, kkrunchy, NSPack, Petite, MPRESS, MEW, FSG, ASPack, PECompact, Yoda's Crypter |
| **StubEvalPending**: stub emulator validated against a spec-built stub, real-sample recovery tracked | 6 | ASProtect, Morphine, nPack, NeoLite, PolyCryptor, Warzone crypter |
| **GreyZoneDetectAndCarve**: virtualizing tier, runtime-keyed handler stream | 3 | VMProtect, Themida, Yoda's Protector |
| **GreyZoneDetectOnly**: commercial protector tier, reported without static recovery | 6 | WinLicense, Enigma Protector, Obsidium, Armadillo, PELock, PE-Protector |
| **DelegatedToDotnet**: managed CLR crypter, recovery delegated to the .NET pass | 2 | DotNetPatcher, NetCryptor |

The recover tier is scored byte-for-byte against real committed originals: UPX `.text` and `.pdata` are bit-identical (the whole loaded image about 96%, the residual being loader-rebuilt relocations and IAT the OS resolves at run time), ASPack and PECompact rebuild the decompressed image with the reconstructed IAT at least 98% byte-identical, and Yoda's Crypter `.rsrc` is byte-identical with its `.text` decrypted to full plaintext. NSPack (about 99% content section) and kkrunchy (byte-exact) are local-only, their vendor fixtures not committed, so those numbers do not reproduce from a clean checkout. The full breakdown is in the [native guide](./languages/native.md).

## Python

| Surface | Count | Families |
|---|---|---|
| **Freezers / packagers** | 9 | PyInstaller 2.x-6.20+, Nuitka (onefile / standalone / module / wheel), cx_Freeze, py2exe, PyOxidizer, shiv, pex, Briefcase, SourceDefender `.pye` |
| **Protector (PyArmor)** | 7 versions | PyArmor v6-v9-pro (default / super / no-wrap); recovered <!-- m:pyarmor_samples -->72<!-- /m --> of 72 real-corpus samples. The v3-v5 RSA-wrapped-key tier is a runtime-key wall. |
| **Source obfuscators (AST-evaluator)** | 20 | Kramer/Specter, Berserker, Jawbreaker, BlankOBF, PlusOBF, Wodx, pyobfuscate.com, pyobfuscate.com (2026 XOR/lambda), PyObfuscator (mauricelambert), python-obfuscator (PyPI), ObfuXtreme, Manglify, Oxyry, pyminifier, online-obfuscator family, Xindex, pyobfus, Pypacker, Patchwork, pyc-zipper |

Jawbreaker's b16/b32/b64 loader shell is decoded statically, but a payload it fetches from a remote paste at run time is absent from the file. ObfuXtreme's AES-CBC/b85/xor static body is recovered; its runtime-payload segment is not in the artifact. python-obfuscator (PyPI), pyobfus, and Pypacker are detect plus partial-peel. Compiled Cython extensions (`.pyd` / `.so`) have their Python-visible surface (function and class names, docstrings, signatures) recovered from the module's symbol tables, with a structural fallback when the binary is stripped. See the [Python guide](./languages/python.md).

## JavaScript / TypeScript / WebAssembly

| Surface | Count | Families |
|---|---|---|
| **JS chain catalog** | 10 | 4 obfuscators (obfuscator.io full pipeline, JS-Confuser, Jscrambler, js-obfuscator (jsobfu)) plus 6 bundler markers (webpack, Vite, Rollup, esbuild, Turbopack, Bun) |
| **JS esoteric encoders + protectors** | separate detectors | JSFuck, aaencode, jjencode, JSFiretruck, Dean Edwards Packer (decoded); JSDefender and Arxan / Digital.ai (detect + static-transform peel); PACE (detect-only) |
| **JS bundlers (unbundler)** | 11 | webpack 4, webpack 5, Vite, Rollup, Rolldown, esbuild, Turbopack, Bun, Parcel, Browserify, SystemJS |
| **WASM obfuscators** | 5 (catalog) | Jscrambler-WASM, Wobfuscator, Tigress-via-Emscripten, Wasmixer (4 reversed); wasm-name-obfuscator is detect + classify only, because its hex renames destroy the original names |

The [JS](./languages/javascript.md) and [WebAssembly](./languages/wasm.md) guides cover each pipeline.

## JVM / Android / .NET

| Surface | Count | Families |
|---|---|---|
| **JVM / Android protectors** | 10 | ProGuard/R8 (mapping replay), Zelix KlassMaster, Allatori, Stringer, DashO, DexGuard (detect + structural peel, with in-class string-decrypt emulation for the keyed-constant variants), BlackObfuscator (DEX deflattening); yGuard, SkidSuite2, JBCO (detect-only) |
| **Android RASP vendors** | 8 | Promon SHIELD, Guardsquare DexGuard RASP, Guardsquare ThreatCast, Appdome, OneSpan, Arxan / Digital.ai, Zimperium zShield, Licel DexProtector |
| **.NET protectors** | <!-- m:dotnet_protectors -->23<!-- /m --> | ConfuserEx, ConfuserEx2, Dotfuscator, Dotfuscator CE, SmartAssembly, Babel, DeepSea, Spices.Net, Goliath, Skater, .NET Reactor, Eazfuscator.NET, CryptoObfuscator, ArmDot, Agile.NET, Obfuscar, Themida (.NET wrapper), ILProtector, MaxToCode, KoiVM, DotNetPatcher, NetCryptor, BitMono |

On .NET, ConfuserEx2 constant decryption is reversed on a real committed sample, the Eazfuscator VM tier is devirtualized at 57 of 57 instructions against an in-repo EazVM virtualizer of our own, and the KoiVM VM tier is devirtualized on a sample produced by the real KoiVM tool (6 of 6 bodies lifted to CIL). ILProtector, MaxToCode, and the Themida/.NET wrapper derive their per-method key in a native loader absent from the artifact, so those bodies are runtime-key walled. See the [JVM and Android](./languages/jvm-android.md) and [.NET](./languages/dotnet.md) guides.

## Lua

The Lua chain catalog is 16 entries: 14 obfuscator families plus the Luau and GLua dialect detectors.

| Surface | Count | Families |
|---|---|---|
| **Obfuscators** | 14 | IronBrew2 (full VM devirtualization), Prometheus, MoonSec V1, MoonSec V2, MoonSec V3, AztupBrew, DarkSec, Boronide, PSU, WeAreDevs, luaobfuscator.com, SLua, Hercules, Luraph |
| **Dialect detectors** | 2 | Luau bytecode, Garry's Mod Lua (GLua) |

IronBrew2 2.7.0 is reversed on real committed output in standard and MAX mode, validated by a real-`lua` execution differential. MoonSec-shape recovery runs against a synthetic bootstrap of our own design pending a real sample. The [Lua guide](./languages/lua.md) walks the devirtualizer.

## Shell

| Surface | Count | Families |
|---|---|---|
| **Shell obfuscators** | 20 (catalog) | PowerShell Invoke-Obfuscation (Token, AST, String, Encoding, Compress, Launcher), Invoke-Stealth, PowerHell, Chameleon, psobf, ISESteroids; Bashfuscator (Token, String, Obfuscate, Compress), bash IFS/eval indirection, and node-bash-obfuscate; Batch `%random%` and set-indirection |

Full VBA p-code decompile (264-opcode table, VBA3/5/6/7) with VBA-stomping detection rounds out the shell pass, alongside Excel 4.0 (XLM) macro-formula recovery (BIFF8/BIFF12 Ptg decode, shared-formula and `Auto_Open` resolution) and PDF maldoc analysis (embedded JavaScript, launch and embedded-file actions, both xref forms, RC4/AESV2 empty-password decrypt). See the [shell guide](./languages/shell.md).

## PHP

| Surface | Count | Families |
|---|---|---|
| **Commercial encoders** | 3 (catalog) | ionCube, SourceGuardian, Zend Guard: envelope detect and wall (the decrypt key is native-loader-resident), with a partial `op_array` skeleton for the legacy statically-keyed cases |

Stacked eval-chain obfuscation (FOPO, Better PHP Obfuscator, and the base64/gzinflate/rot13/XOR layer set) and Phar archives are peeled and walked in the same pass. See the [PHP guide](./languages/php.md).

## Other runtimes

| Ecosystem | Coverage |
|---|---|
| **Go** | garble report graded None / Detected / Partial / Full; `garble -literals` simple and full-key literals recovered through static blob pairing plus bounded x86-64 thunk/inline emulation. Type names resolved above an <!-- m:go_typename_pct -->85%<!-- /m --> floor on the committed go1.26.3 fixture. |
| **Ruby** | MRI/YARV 2.6-3.4 and mruby recompile-equivalence decompile; Ruby2Exe and Ocra freezers detected; JRuby and TruffleRuby AOT classified. |
| **BEAM** | `.beam` and `.ez` chunk parse, Core Erlang lift, Elixir `Dbgi` quoted-AST recovery. |
| **Swift / Obj-C** | Mach-O class-dump plus SwiftConfidential and SwiftShield rename-undo; `objc_msgSend` call sites in recovered native bodies resolved to selector and receiver class. |
| **ActionScript 3** | SWF parse and AVM2 disasm; commercial obfuscators (secureSWF, DoSWF, Kindi, Irrfuscator, swfLock) detect-only. |
| **Hermes / Flutter** | Hermes bytecode v60-v96 lift; Flutter Dart kernel byte-exact body recovery and ARM64 AOT disasm. |
| **Containers / archives / filesystems / firmware** | <!-- m:containers_formats -->98<!-- /m --> formats detected, all <!-- m:containers_formats -->98<!-- /m --> with in-tree extractors that write member bytes. |

## The `disrobe auto` chain

`disrobe auto` is the front door to the whole catalog. It fingerprints the input, picks the first pass, runs it, re-fingerprints the output, and follows the capability resolver until no further pass applies or the depth cap is hit. Detection spans 23 pass crates.

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
