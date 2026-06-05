# Command reference

The authoritative source is always `disrobe <command> --help`. This page is a complete map of the command surface. `[--out]` and the standardized `[--emit ...]` selector are available on most passes; see the [global flags](./global-flags.md) for flags that apply everywhere.

## Python

| Command | Purpose |
|---|---|
| `disrobe py decompile <pyc>` | Decompile a `.pyc` to source. `--backend native\|pycdc\|decompyle3\|uncompyle6` (default `native`). |
| `disrobe py disasm <pyc>` | Per-instruction disassembly (1.0-3.15 + PyPy/MicroPython/Jython/IronPython/Brython). |
| `disrobe py deob <src>` | Peel a source obfuscator. `--cleanup` runs a ruff-AST fold. |
| `disrobe py extract <archive>` | Extract a wheel / sdist / egg / `.whl` / `.zip` / any archive. |
| `disrobe py sourcedefender <pye>` | Decrypt a SourceDefender `.pye` envelope. |
| `disrobe pyarmor unpack <py>` | Unpack PyArmor v6-v9-pro. `--allow-dynamic`, `--mode`, `--target`, `--allow-bcc`, `--strict`. |
| `disrobe pyinstaller extract <exe>` | Extract a PyInstaller build (2.1-6.x, AES decrypt). |
| `disrobe pyinstaller detect <exe>` | Report cookie / Python version / TOC offsets without extracting. |
| `disrobe pyfreeze extract <exe>` | Extract cx_Freeze / py2exe / shiv / pex / PyOxidizer / Briefcase. |
| `disrobe pyfreeze detect <exe>` | Identify the freezer without extracting. |
| `disrobe nuitka detect\|extract\|symbols\|decompile\|const <input>` | Nuitka flavor detect, `--onefile` extract, symbol scan, constants decompile, single `.const` decode. |

## JavaScript / WebAssembly

| Command | Purpose |
|---|---|
| `disrobe js deob <js>` | Deobfuscate (obfuscator.io, JS-Confuser, Jscrambler, esoteric encoders). |
| `disrobe js unbundle <js>` | Split a bundle into per-module sources (10+ bundlers). |
| `disrobe js inspect <blob>` | Inspect V8 `.jsc` / Node SEA / nexe / nw.js / Electron `.asar`. |
| `disrobe wasm decompile <wasm>` | Lift to `--target json\|rust\|ts\|wat\|c`. |
| `disrobe wasm deob <wasm>` | Reverse 5 Wasm obfuscator families. |
| `disrobe wasm component <wasm>` | Parse a Component Model envelope. |
| `disrobe wasm gc-types <wasm>` | Recover the GC type graph. |

## JVM / Android / .NET

| Command | Purpose |
|---|---|
| `disrobe jvm decompile <class\|jar\|dex\|apk>` | Decompile via `--backend cfr\|vineflower\|procyon\|jadx`. |
| `disrobe jvm extract <jar\|apk>` | Extract container + dump classfile inventory. |
| `disrobe jvm backends` | Report JVM/Android backends on PATH. |
| `disrobe dotnet decompile <dll\|exe>` | Decompile via `--backend ilspy\|dnspy\|dnspyex\|de4dot`. |
| `disrobe dotnet analyze <dll>` | PE/CLR metadata, protector detection, R2R + NativeAOT probe. |
| `disrobe dotnet backends` | Report .NET backends on PATH. |

## Native

| Command | Purpose |
|---|---|
| `disrobe native decompile <bin>` | Ghidra-headless decompile. |
| `disrobe native symbols <bin>` | Dump symbols, sections, imports, debug info. |
| `disrobe native unpack <bin>` | Detect + unpack UPX/Petite/NSPack/MEW/FSG/MPRESS. |
| `disrobe native entropy <bin>` | 4KB sliding-window Shannon entropy. |
| `disrobe native signatures <bin>` | Crypto-constant fingerprints; `--flirt <sig>` to match a FLIRT DB. |
| `disrobe native fingerprint <bin>` | Aggregate crypto + FLIRT + string-xref sidecar. |
| `disrobe native sbom <bin>` | CycloneDX 1.5 SBOM from cargo-auditable metadata. |
| `disrobe native graph <bin>` | Import/export table as Graphviz DOT. |

## Other languages

| Command | Purpose |
|---|---|
| `disrobe go recover\|report <bin>` | Go symbol recovery / build fingerprint. |
| `disrobe lua decompile\|deob\|detect <chunk>` | Lua decompile / obfuscator peel / dialect detect. |
| `disrobe php decode\|peel\|phar <input>` | Encoder decode / eval-chain peel / Phar walk. |
| `disrobe ruby analyze\|detect <input>` | Ruby flavor analysis / detection. |
| `disrobe beam parse\|lift\|disasm <beam>` | BEAM chunk parse / Core Erlang lift / Code disasm. |
| `disrobe pickle disasm\|decompile\|safety\|trace\|polyglot\|model-detect <input>` | Pickle static analysis suite. |
| `disrobe swift classdump\|unshield\|confidential <input>` | Swift/ObjC class-dump and rename-undo. |
| `disrobe macho dump\|classdump\|slices <input>` | Mach-O / fat / `.ipa` inspection. |
| `disrobe as3 disasm\|tags <swf>` | AS3 DoABC disasm / SWF tag list. |
| `disrobe hermes lift\|disasm\|info <bundle>` | Hermes JS-surface lift / disasm / header. |
| `disrobe flutter dump\|decompile\|obfmap <input>` | Flutter Dart AOT inspection. |
| `disrobe mobile detect\|extract\|hermes-disasm\|flutter-dump <input>` | Mobile runtime pipeline. |

## Chain, envelope, and forensics

| Command | Purpose |
|---|---|
| `disrobe auto <input>` | Auto-detect + chain. `--max-depth`, `--capture-stages`, `--emit recovery`. |
| `disrobe chain <input>` | Explicit pipeline. `--chain 'auto:8'` or `'pyarmor+py-decompile'`, `--chain-pin`, `--capture-stages`. |
| `disrobe diff <left> <right>` | Structurally diff two `chain.json` documents. |
| `disrobe guard verify\|check ...` | Verify stage hashes / deny edits to ground-truth stages. |
| `disrobe envelope create\|inspect\|verify\|diff\|migrate-check <dr>` | `.dr` envelope operations. |
| `disrobe verify <dr>` | Alias for `disrobe envelope verify`. |
| `disrobe scan <path>` | Scan raw bytes for leaked credentials. |
| `disrobe yara <path>` | Parse a YARA ruleset into a typed AST (read-only, no matching). |
| `disrobe status` | Summarize `./out/`: per-stage counts, sizes, manifests. |
| `disrobe context --out <dir>` | Summarize a recovery report (status, confidence, verdict, provenance). |

## Workspace, agents, and meta

| Command | Purpose |
|---|---|
| `disrobe init [--ide claude\|cursor\|windsurf\|aider]` | Scaffold a `.disrobe/` workspace. |
| `disrobe annot refresh\|regenerate` | Rebuild a symbol annotation file. |
| `disrobe rename <old> <new> [--note]` | Record an append-only rename. |
| `disrobe passes` | List registered passes. |
| `disrobe explain <code>` | Look up a `DR-*` error code. |
| `disrobe doctor [--auto-install] [-y]` | Probe ~50 optional external tools. |
| `disrobe install <tool> [--list]` | Install one optional tool via the native package manager. |
| `disrobe install-deps <dep> [--all]` | Install heavyweight deps (Ghidra) from upstream releases. |
| `disrobe serve [--stdio\|--mcp\|--grpc]` | Run the daemon. See [the daemon](./serve.md). |
| `disrobe completions <shell> [--install]` | Generate shell completions. |
| `disrobe man [--out <dir>]` | Generate man pages. |
| `disrobe bug-report [--out -]` | Collect environment into a markdown bug report. |
| `disrobe self-update [--check-only]` | Print self-update guidance (source-only distribution). |
