# Passes and pass selection

A **pass** is the unit of work in `disrobe`. Each pass lives in its own crate, implements a shared trait, and registers a detector that scores how confidently it recognizes a given input. `disrobe auto` picks the next pass by comparing detector verdicts, not by matching capability descriptors between passes; see [Pass selection](#pass-selection) below.

## Registered passes

Run `disrobe passes` for the live list. As of the current release:

| Pass | Capability summary |
|---|---|
| `pyarmor` | PyArmor v6 / v7 (dynamic-hook) + v8 / v9-pro static unpack. |
| `pyinstaller` | PyInstaller 2.x-6.20+ extract + AES-CTR / CFB decrypt. |
| `pyfreeze` | cx_Freeze / py2exe / shiv / pex / PyOxidizer / Briefcase detect + extract. |
| `nuitka` | `--onefile` payload extract (zstd) + symbol / constants scan. |
| `py` | Deobfuscate (peel + cleanup) / disassemble / decompile / extract / SourceDefender decrypt. |
| `js` | Deobfuscate (string-array + unminify + scope-aware rename) / unbundle, detecting <!-- m:js_bundlers -->11<!-- /m --> bundler families. |
| `wasm` | Analyze / decompile (JSON / Rust / TypeScript / WAT / C) / reverse <!-- m:wasm_reversers -->4<!-- /m --> obfuscator families (plus wasm-name-obfuscator detect + classify). |
| `envelope` | `.dr` create / inspect / verify / diff / migrate-check. |
| `query` | Query a Disasm- or Mir-rung `.dr` IR: functions / calls-to / xrefs-to / string-decoders / complexity-over / capability sites. |
| `capabilities` | Match a binary against built-in capability rules with evidence addresses and MITRE ATT&CK / MBC tags. |
| `taint` | Track source-to-sink flows across normalized IR for native, Wasm, JVM, Dalvik, and `.dr` inputs. |
| `frisk` | Scan files or recovered source trees for secrets, endpoints, cloud buckets, manifest exposure, and IOCs with file/line/column evidence. |
| `prowl` | Harvest URLs and IOCs from public archives and threat-intel feeds with explicit network access, rate limits, filters, proxy support, and API-key/keyring support. |
| `scan` | Scan raw bytes for leaked credentials. |
| `ioc` | Extract URLs, domains, IPs, emails, paths, registry keys, wallets, and crypto constants, including one base64/hex decode layer. |
| `indicators` | Merge `frisk`, `ioc`, and `prowl` JSON into `disrobe.indicators/v0` with per-indicator source provenance and target export. |
| `strings` | Extract ASCII and UTF-16LE strings with optional XOR, base64, ROT, and stack-string decoding. |
| `behavior` | Summarize static behavior across network, filesystem, process, registry, crypto, anti-analysis, and dynamic-code categories. |
| `yara` | Parse YARA rules into a typed AST or generate a candidate rule from an artifact. |
| `native` | In-tree decompile to C and Rust by default, with ghidra-headless as an opt-in backend / symbol dump / unpack / devirt / entropy / crypto signatures / disasm / callgraph / patch / sigmaker / diff. |
| `jvm` | Classfile / `.jar` / `.dex` / `.apk` decompile via CFR / Vineflower / Procyon / JADX. |
| `apk` | AndroidManifest.xml decode + resource id-to-name map + signer-cert SHA-256. |
| `dotnet` | .NET PE decompile via ILSpy / dnSpyEx / de4dot + protector detection. |
| `hermes` | React Native Hermes bundle disasm + JS surface lift. |
| `macho` | Mach-O / fat / `.ipa` dump + ObjC + Swift class-dump. |
| `lua` | Lua 5.1-5.4 / LuaJIT / Luau / GLua decompile + obfuscator peel. |
| `php` | Encoder decode (phar / ionCube / SourceGuardian / ZendGuard) + eval-chain peel. |
| `ruby` | MRI / YARV / mruby / JRuby / TruffleRuby / Ruby2Exe / Ocra analysis. |
| `beam` | `.beam` IFF parse + Core Erlang lift + Code chunk disasm. |
| `pickle` | Disasm + decompile + safety + symbolic trace + polyglot + ML model detect. |
| `go` | pclntab + moduledata + garble report + embed.FS extraction. |
| `swift` | Swift / ObjC class-dump + SwiftShield undo + Confidential XOR-decrypt. |
| `as3` | ActionScript 3 `.swf` DoABC tag disasm. |
| `flutter` | Dart AOT / libapp.so dump + obfuscation_map parse. |
| `catalog` | List the live obfuscator, packer, protector, freezer, and bundler registry by ecosystem and recovery tier. |
| `chain` | Explicit pass pipeline orchestrator. |
| `serve` | HTTP daemon + WebSocket stream + LSP-stdio + gRPC + MCP. |

## Pass selection

Rather than hard-coding which pass follows which, every pass registers a `Detector` (`chain::detector::Detector` in `disrobe-core`) that inspects the current bytes and, if it recognizes them, returns a `DetectVerdict`: a pass ID, a format tag, a family (`obfuscator-wrapper`, `packer-archive`, `interpreter-bytecode`, `source`, `container`, `native-format`, or `unknown`), a confidence score, and a specificity rank.

`PassRegistry::run_all` (`chain/registry.rs`) runs every registered detector against the bytes. Six extraction-first passes (`nuitka.extract`, `pyinstaller.extract`, `pyfreeze.extract`, `pyarmor.unpack`, `binfmt.container`, `sourcedefender.decrypt`) are tried before the rest, and the sweep stops early the moment one of them returns a `High`-band verdict (confidence >= 0.90) with specificity <= 30. A raw confidence buckets into `ConfidenceBand::Low` (< 0.70), `Medium` (0.70-0.89), or `High` (>= 0.90).

A `SelectionPolicy` then picks the winner among whatever verdicts came back: candidates below its minimum confidence (0.5 by default) are dropped, and the survivors are ranked by `precedence::compare` (`chain/precedence.rs`), which breaks ties in order: confidence band, then raw confidence, then the lower specificity value, then a fixed family-precedence table (`obfuscator-wrapper` beats `packer-archive` beats `interpreter-bytecode` beats `source` beats `container` beats `native-format` beats `unknown`), then the lexically smaller pass ID.

The chain driver (`chain/state_machine.rs`) runs this selection once per queued artifact, executes the winning pass, and re-runs detection on its output to decide what happens next. A branch ends when no verdict clears the minimum confidence (`Stalled`), when the same output bytes reappear (`Cycle`), or when the depth cap or cumulative-output budget is exceeded (`CapReached`). This is why `disrobe auto` can detect that a PyInstaller archive contains a PyArmor-protected module and route it through the unpack-then-decompile chain without any per-combination glue code.

## Standardized emits

Every pass exposes the same twelve emit kinds:

```text
source  disasm  ast  cfg  ir  manifest  sourcemap  symbols  strings  imports  signatures  report
```

Pass `--emit source,disasm,report` (comma-separated) to select a subset, or `--all-emits` on passes that support it to write every kind. A pass that cannot produce a given emit writes an explicit stub:

```json
{
  "schema": "disrobe.emit.stub/v0",
  "pass": "pyarmor",
  "emit_kind": "source",
  "applicable": false,
  "error_code": "DR-IR-NotApplicable",
  "reason": "pyarmor pass does not produce source; chain with disrobe py decompile"
}
```

A downstream tool can request any emit from any pass and get a well-formed, self-describing answer: either the artifact or a "not applicable here, chain with X."

## Error codes

Every failure carries a `DR-<DOMAIN>-<NNNN>` code rendered through miette diagnostics. Look any code up with:

```sh
disrobe explain DR-PYARM-0050
disrobe explain CLI-1            # short form also works
```
