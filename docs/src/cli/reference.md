# Command reference

The authoritative source is always `disrobe <command> --help`. This page is a complete map of the command surface. `[--out]` and the standardized `[--emit ...]` selector are available on most passes; see the [global flags](./global-flags.md) for flags that apply everywhere.

## Python

| Command | Purpose |
|---|---|
| `disrobe py decompile <pyc>` | Decompile a `.pyc` to source. `--backend native` (the only supported value). `--no-roundtrip` skips the recompile-equivalence check. |
| `disrobe py disasm <pyc>` | Per-instruction disassembly (1.0-3.15 + PyPy/MicroPython/Jython/IronPython/Brython). |
| `disrobe py deob <src>` | Peel a source obfuscator. `--cleanup` runs a ruff-AST fold. |
| `disrobe py extract <archive>` | Extract a wheel / sdist / egg / `.whl` / `.zip` / any archive. |
| `disrobe py sourcedefender <pye>` | Decrypt a SourceDefender `.pye` envelope. |
| `disrobe pyarmor unpack <py>` | Unpack PyArmor v6-v9-pro. `--allow-dynamic` permits the dynamic-hook fallback (trusted/sandboxed samples only). `--dynamic-timeout <SECS>`. `--mode auto\|standard\|super`. `--target <PYVER>`. `--allow-bcc`. `--strict`. `--no-cextract` / `--cextract-only`. `--all-emits` writes stubs for all 12 emit kinds. `--cache <DIR>`. |
| `disrobe pyinstaller extract <exe>` | Extract a PyInstaller build (2.x-6.20+, AES decrypt). |
| `disrobe pyinstaller detect <exe>` | Report cookie / Python version / TOC offsets without extracting. |
| `disrobe pyfreeze extract <exe>` | Extract cx_Freeze / py2exe / shiv / pex / PyOxidizer (experimental, unvalidated) / Briefcase. |
| `disrobe pyfreeze detect <exe>` | Identify the freezer without extracting. |
| `disrobe nuitka detect\|extract\|symbols\|decompile\|const <input>` | Nuitka flavor detect, `--onefile` extract, symbol scan, constants decompile, single `.const` decode. |

## JavaScript / WebAssembly

| Command | Purpose |
|---|---|
| `disrobe js deob <js>` | Deobfuscate (obfuscator.io, JS-Confuser, Jscrambler, esoteric encoders). |
| `disrobe js unbundle <js>` | Split a bundle into per-module sources (<!-- m:js_bundlers -->11<!-- /m --> bundlers). |
| `disrobe js v8 <blob>` | Inspect V8 `.jsc` / Node SEA / nexe / nw.js / Electron `.asar`. |
| `disrobe wasm decompile <wasm>` | Lift to `--target json\|rust\|ts\|wat\|c`. |
| `disrobe wasm deob <wasm>` | Reverse Wasm obfuscator families. |
| `disrobe wasm component <wasm>` | Parse a Component Model envelope. |
| `disrobe wasm types <wasm>` | Recover the GC type graph. |
| `disrobe wasm lift-gc <wasm>` | Lift the recovered GC type graph to typed Rust + TypeScript struct / array source. |

## JVM / Android / .NET

| Command | Purpose |
|---|---|
| `disrobe jvm decompile <class\|jar\|dex\|apk>` | Decompile via `--backend cfr\|vineflower\|procyon\|jadx`. |
| `disrobe jvm extract <jar\|apk>` | Extract container + dump classfile inventory. |
| `disrobe jvm backends` | Report JVM/Android backends on PATH. |
| `disrobe jvm retrace` | Retrace an obfuscated stack frame back to class/method/line through a ProGuard/R8 `mapping.txt` (`--mapping`, `--class`, `--method`, `--line`). |
| `disrobe apk <apk>` | Decode the binary AndroidManifest.xml, map resource ids to names, and dump each signer certificate's SHA-256. `--out <DIR>` writes the decoded manifest and resource table to disk. |
| `disrobe dotnet decompile <dll\|exe>` | Decompile via `--backend ilspy\|dnspy\|dnspyex\|de4dot`. |
| `disrobe dotnet deobfuscate\|peel <dll\|exe>` | Detect the .NET protector and peel it: decrypt resources, recover constants/strings, classify renamable identifiers, strip watermarks. `--protector <name>` forces one. |
| `disrobe dotnet analyze <dll>` | PE/CLR metadata, protector detection, R2R + NativeAOT probe. |
| `disrobe dotnet backends` | Report .NET backends on PATH. |

## Native

| Command | Purpose |
|---|---|
| `disrobe native decompile <bin>` | In-tree x86-64 -> C/Rust and AArch64 -> pseudo-C decompile, default (`--backend native --format c\|rust`). AArch64 whole-program call resolution is limited to linked ELF inputs; relocatable AArch64 objects fail before output. `--format rust` and the `types.json` sidecar are x86-64 only. C output is graded against real gcc/clang and x86-64 Rust output against rustc. On the AArch64 path a symbolic devirtualizer folds proven-dead conditional arms before structuring (on by default; `--no-devirt` disables it). `--backend ghidra` drives ghidra-headless instead: `--emit source,disasm,ast,cfg,ir,manifest,sourcemap,symbols,strings,imports,signatures,report`. |
| `disrobe native symbols <bin>` | Dump symbols, sections, segments, imports, and debug info. |
| `disrobe native identify <bin>` | Fingerprint compiler / packer / protector / installer, each routed to its pass. |
| `disrobe native unpack [bin]` | Detect + unpack the <!-- m:native_tier_implemented -->12<!-- /m --> Implemented-tier families (<!-- packer-roster:implemented -->Donut, sRDI, UPX, ASPack, Petite, MPRESS, FSG, PECompact, Yoda's Crypter, NSPack, MEW, kkrunchy<!-- /packer-roster -->) via in-house decoders + x86 stub emulator. Input is optional; `--list` shows all supported packers (the full detect catalog is <!-- m:native_catalog_entries -->27<!-- /m --> packers and protectors; Yoda's Protector needs the original image for a diff-based carve, and the commercial protector tier is reported without static recovery). |
| `disrobe native devirt <bin>` | Devirtualize the bytecode-VM tier: recover the handler table, lift to a re-executable IR + pseudo-code. |
| `disrobe native export <bin>` | Unpack, recover symbols, and export a backend-ready bundle: a rebuilt loadable PE + a Ghidra post-script / IDAPython / JSON symbol map. `--format ghidra\|ida\|json` (default `ghidra`). |
| `disrobe native disasm <bin>` | Per-function listing / `--emit cfg-dot` CFG / `--emit json` / `--raw` linear sweep (`--syntax nasm\|intel\|att\|masm`). Accepts a `.dr` envelope. |
| `disrobe native callgraph <bin>` | Whole-program call graph as Graphviz DOT. |
| `disrobe native patch <bin>` | Rewrite bytes at a VA (or nop a span) and revalidate the image. |
| `disrobe native sigmaker <bin>` | Wildcarded byte signature from a function, uniqueness-tested. |
| `disrobe native diff <a> <b>` | Match functions across two builds by content + CFG fingerprint. |
| `disrobe native entropy <bin>` | 4KB sliding-window Shannon entropy; ASCII heat-strip + byte histogram + packed-region runs. `--format text\|json\|svg` (default `text`), `--svg <out>` for a dark-theme entropy map with section overlays. |
| `disrobe native signatures <bin>` | Crypto-constant fingerprints (AES, SHA, ChaCha20). `--flirt <sig>` to match a FLIRT DB. |
| `disrobe native fingerprint <bin>` | Aggregate crypto-constant + FLIRT + string-xref sidecar at `.disrobe/fingerprints/<stem>.json`. `--flirt <sig>`. |
| `disrobe native sbom <bin>` | CycloneDX 1.5 SBOM from cargo-auditable metadata embedded in the binary. |
| `disrobe native graph <bin>` | Import/export table as Graphviz DOT. |
| `disrobe query <bin\|.dr> <q...>` | Queryable IR: `functions`, `calls-to <sym>`, `xrefs-to <sym>`, `string-decoders`, `complexity-over <n>`, `capability <network\|crypto\|filesystem\|process>`. Accepts a raw binary or a Disasm- or Mir-rung `.dr` envelope. |
| `disrobe capabilities <bin\|.dr>` | Rule engine over the IR, mapping behaviors to MITRE ATT&CK + MBC with per-match evidence. |
| `disrobe taint <input>` | Track a value from source calls to sink calls across the normalized IR (native / wasm / JVM / Dalvik / `.dr`). `--source <SYM>` / `--sink <SYM>` override the built-in source/sink sets (repeatable). |

## Other languages

| Command | Purpose |
|---|---|
| `disrobe go recover\|info <bin>` | Go symbol recovery / build fingerprint. |
| `disrobe lua decompile\|deobfuscate\|detect <chunk>` | Lua decompile / obfuscator peel / dialect detect. |
| `disrobe php decode\|deobfuscate\|extract <input>` | Encoder decode / eval-chain peel / Phar extract. |
| `disrobe shell deob\|detect <input>` | PowerShell / Bash / Batch / VBA deobfuscate (Invoke-Obfuscation, Invoke-Stealth, Bashfuscator, ...) and dialect / family detect. |
| `disrobe ruby decompile\|detect <input>` | Ruby artifact analysis / flavor detection. |
| `disrobe beam parse\|lift\|disasm <beam>` | BEAM chunk parse / Core Erlang lift / Code disasm. |
| `disrobe pickle disasm\|decompile\|safety\|trace\|polyglot\|ml-detect <input>` | Pickle static analysis suite. |
| `disrobe swift classdump\|shield-undo\|xor-decrypt <input>` | Swift/ObjC class-dump, SwiftShield rename-undo, explicit-key XOR blob decode. |
| `disrobe macho dump\|classdump\|fat <input>` | Mach-O / fat / `.ipa` inspection. |
| `disrobe as3 disasm\|tags <swf>` | AS3 DoABC disasm / SWF tag list. |
| `disrobe hermes decompile\|disasm\|info <bundle>` | Hermes JS-surface lift / disasm / header. |
| `disrobe flutter dump\|decompile\|kernel\|disasm\|map <input>` | Flutter Dart AOT + kernel inspection. |
| `disrobe mobile detect\|extract\|hermes\|flutter\|recon <input>` | Mobile runtime pipeline. |

## Chain, envelope, and forensics

| Command | Purpose |
|---|---|
| `disrobe detect <input>` | Run every obfuscator/packer catalog detector against a file and report each hit (pass, obfuscator, confidence, markers). |
| `disrobe identify <input>` | Fingerprint the compiler / linker / packer / protector / installer of a PE / ELF / Mach-O with structural evidence and the pass that handles each (top-level shortcut for `native identify`; alias `die`). |
| `disrobe catalog [ecosystem]` | List the supported obfuscator, packer, protector, freezer, and bundler registry by ecosystem. The live binary reports <!-- m:catalog_family_total -->169<!-- /m --> families across <!-- m:catalog_ecosystems -->15<!-- /m --> ecosystems; filter with `python`, `js`, `jvm`, `dotnet`, `native`, `go`, `wasm`, `ruby`, `lua`, `php`, `beam`, `as3`, `mobile`, `swift`, or `shell`. `--json` emits `{ family_count, ecosystem_count, ecosystems[] }`. |
| `disrobe auto <input>` | Auto-detect + chain. `--max-depth <N>` (default 8), `--capture-stages`, `--emit recovery`, `--dry-run`. A directory input is [batch-processed](./batch.md) recursively (`--include <GLOB>`, `--exclude <GLOB>`, `--batch-max-depth <N>`, `--jobs <N>`) into an aggregate `manifest.json`. |
| `disrobe chain <input>` | Explicit pipeline. `--chain 'auto:8'` or `'pyarmor+py-decompile'`, `--chain-pin <ver>`, `--capture-stages`. |
| `disrobe diff <left> <right>` | Structurally diff two `chain.json` documents (passes, stage BLAKE3 hashes, sizes, verdicts). |
| `disrobe guard verify <subject> --reference <ref>` | Verify a subject `chain.json`'s per-stage output hashes against a committed reference. |
| `disrobe guard check <path> [--root <subtree>...]` | Deny writes to ground-truth stage paths (`out/**/stages`, `out/**/final`, `.disrobe-stage-lock`). `--root` adds extra protected subtrees (repeatable). |
| `disrobe envelope create\|inspect\|verify\|diff\|migrate-check <dr>` | `.dr` envelope operations; `migrate-check` takes source and target envelopes. |
| `disrobe verify <dr>` | Alias for `disrobe envelope verify`. |
| `disrobe scan <path>` | Scan raw bytes for leaked credentials. |
| `disrobe frisk <path> [--format text\|json\|sarif]` | Scan files, directories, APKs, and recovered source for secrets, endpoints, buckets, manifest exposure, and IOCs. Rule packs use `--pattern <FILE>`, suppressions use `--suppress <SUBSTR>`, and baselines use `--emit-baseline` / `--baseline <FILE>`. |
| `disrobe prowl [target...]` | Harvest URLs and IOCs from public archives and threat-intel feeds. Inputs can come from arguments, `--targets-file`, `--stdin`, or `--recon-input`. Sources are `wayback`, `commoncrawl`, `otx`, `urlscan`, `crtsh`, `urlhaus`, `threatfox`, and `virustotal` (`vt` alias). Filters include `--subs`, `--blacklist`, `--from`, `--to`, `--mc`, `--fc`, `--mt`, `--ft`, `--ioc`, `--fp`, and `--no-iocs`. Network controls include `--proxy`, `--timeout`, `--concurrency`, `--per-host-rps`, `--max-pages`, `--max-urls`, `--max-iocs`, and `--retries`. Keys resolve from `--api-key provider=key`, provider env vars, a permissions-checked TOML file, or `disrobe prowl keyring set\|get\|rm\|list <provider>`. |
| `disrobe ioc <path> [--format text\|json\|sarif] [--defang]` | Extract [indicators of compromise](./analysis-depth.md#ioc-extraction) (URLs, IPs, domains, emails, paths, registry keys, wallets, crypto constants); decodes one base64/hex layer. |
| `disrobe indicators <json...> [--targets-only] [--format text\|json]` | Merge `frisk`, `ioc`, and `prowl` JSON artifacts into `disrobe.indicators/v0`, deduplicate by class and value, retain source provenance, or print only network targets for `prowl --targets-file`. |
| `disrobe strings <path> [--min-len N] [--no-decode]` | [Cross-format string extraction](./analysis-depth.md#string-extraction): ASCII + UTF-16LE, with single-byte XOR / base64 / ROT-n / stack-string deobfuscation. |
| `disrobe behavior <path>` | [Behavior / capability summary](./analysis-depth.md#behavior-summary) across 7 categories, tagged with MITRE ATT&CK technique ids. |
| `disrobe yara parse <path>` | Parse a YARA ruleset into a typed AST (read-only, no matching). |
| `disrobe yara generate <input> [--name N] [--sha256 H] [--date D]` | [Generate a candidate YARA rule](./analysis-depth.md#yara-rule-generation) from an artifact; output round-trips through the parser. |
| `disrobe status` | Summarize `./out/`: per-stage counts, sizes, manifests. |
| `disrobe context --out <dir>` | Summarize a recovery report (status, confidence, verdict, provenance). |
| `disrobe report <dir-or-input> [--format text\|json\|markdown\|html]` | Consolidate a completed run (or raw input) into a [forensic summary](./report.md): identity, topology, per-stage verdicts/scores, artifact inventory, timings. `--format html` emits a self-contained, offline, dark-theme report (inline SVG bars, IOC + ATT&CK tables, XSS-escaped). |

## Workspace and meta

| Command | Purpose |
|---|---|
| `disrobe init [--ide <flavor>] [--force]` | Scaffold a `.disrobe/` workspace and optional editor settings. |
| `disrobe config [show]` | Print the resolved `.disrobe.toml` config (honors `--json`). See [project configuration](./config.md). |
| `disrobe config init [--out <path>] [--force]` | Write a documented `.disrobe.toml` template. |
| `disrobe annot refresh\|regenerate` | Rebuild a symbol annotation file. |
| `disrobe rename <old> <new> [--note]` | Record an append-only rename. |
| `disrobe passes` | List every registered pass with a one-line capability summary. |
| `disrobe explain <code>` | Look up a `DR-*` error code and print its description and common fixes. |
| `disrobe doctor [--auto-install] [-y]` | Probe ~50 optional external tools; report installed, missing, or stale. |
| `disrobe install <tool> [--list] [-y] [--dry-run]` | Install one optional tool via the native package manager. |
| `disrobe install-deps [<dep>] [--all] [--dry-run]` | Install heavyweight deps (Ghidra) from upstream releases. |
| `disrobe serve [--bind <ADDR>] [--stdio\|--mcp\|--grpc]` | Run the daemon. See [the daemon](./serve.md). |
| `disrobe completions <shell> [--install] [--rc-file <PATH>]` | Generate shell completions (bash, zsh, fish, PowerShell, elvish). |
| `disrobe man [--out <dir>]` | Generate man pages (one `.1` per subcommand). |
| `disrobe bug-report [--out <PATH\|->]` | Collect environment, manifests, and tooling versions into a markdown bug report. |
| `disrobe self-update [--check-only] [--dry-run]` | Print self-update guidance (source-only distribution; no network by default). |
