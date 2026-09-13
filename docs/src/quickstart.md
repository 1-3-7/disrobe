# Quickstart

This walkthrough takes a local file through automatic recovery, inspects the result, and shows how to select a direct command when you know the format. Replace the example filenames with your own inputs.

## Check the installation

Follow [installation](./installation.md), then confirm which binary and optional tools are available:

```sh
disrobe --version
disrobe doctor
```

`doctor` reports installed, missing, and stale external tools. The in-house recovery paths do not require all of them. Install a tool when the command or verification step you need requires it; see [optional backends](./installation.md).

For a first run, use a file you own or a trusted compiled fixture. For an untrusted sample, read the [handling guidance](./forensics-safety.md) first. The default recovery path does not execute the input.

## Auto-detect and chain

```sh
disrobe auto suspect.exe --out recovered/ --capture-stages
disrobe context --out recovered/
disrobe report recovered/ --format html > recovery.html
```

`auto` identifies the input and selects a recovery chain from the available passes. Open `recovery.html` for the artifact inventory, evidence, and stage outcomes. `context` gives a shorter terminal view of the passes that ran, their confidence tiers, the final verdict, and provenance.

The output directory contains `chain.json`, `recovery.json`, `anti-analysis.json`, and `report.json`. Use these structured reports when another tool needs the topology, recovery status, or forensic summary. Check the input identity and any incomplete or failed stages before treating the recovered files as a complete account of the input. See [reading a result](./reading-a-result.md) for the status vocabulary and next steps.

The selected passes depend on the bytes recovered at each stage:

| Input | Automatic route and output |
|---|---|
| UPX-packed Go executable | `native.packer-unpack` recovers the executable; `go.classify` recovers Go runtime metadata and symbols |
| PyInstaller containing a supported PyArmor wrapper | `pyinstaller.extract` extracts members; `pyarmor.unpack` uses available runtime/key material; `py.decompile` handles recovered bytecode |
| Android APK | `jvm.classify` recovers DEX source, manifest information, and supported child artifacts |
| Electron ASAR | `webview.carve` extracts the frontend tree; recognized JavaScript children can continue through `js.deob` |

Read the [pass list](passes.md#commands-and-auto-chain-passes) and the recovery report for the route and support tier actually selected. A missing key or unsupported variant can end a branch before source recovery.

Use `--capture-stages` to mirror the exact bytes written by each executed pass under `<out>/NN-<pass>/` and link the terminal stage or stages under `<out>/final/`. These are exact stage records; a decompiler's source output is not a byte-identical copy of the compiled input. Cap the chain depth with `--max-depth` (default 8).

## Per-language one-liners

Choose a direct command when you know the format or want to inspect one layer of a chain. The output path in each example identifies the source file, extracted tree, or report to inspect next. Run `disrobe <command> --help` before relying on a backend or emit that is not shown here.

### Python bytecode and frozen applications

Decompile a `.pyc`, inspect its instructions, clean obfuscated source, or extract an application bundle:

```sh
disrobe py decompile module.pyc --out recovered/
disrobe py disasm module.pyc --out trace.txt
disrobe py deob obfuscated.py --out clean.py --cleanup
disrobe pyinstaller extract onefile.exe --out out/
disrobe pyarmor unpack protected.py --out out/
disrobe nuitka extract app.exe --out out/
```

Python's default round-trip check needs a matching interpreter. Read its result before relying on the emitted source; a missing interpreter leaves the comparison unperformed. [Python recovery](./languages/python.md) describes the comparison and version limits.

PyArmor v6/v7 may require the dynamic-hook fallback. That path executes the sample and is disabled unless you add `--allow-dynamic`. Use it only inside an isolated sandbox with no network or sensitive mounts. PyArmor v8/v9 and `--allow-bcc` remain static.

### JavaScript, WebAssembly, and embedded frontends

Clean a bundle, split its modules, lift WebAssembly, or extract a desktop application's frontend:

```sh
disrobe js deob bundle.min.js --out clean.js
disrobe js unbundle app.bundle.js --out src/
disrobe wasm decompile module.wasm --target rust --out lifted.rs
disrobe webview desktop.exe --out frontend/
```

### JVM, Android, and .NET

These examples request installed external backends. Check `doctor` and the command's reported backend: availability and fallback behavior are command-specific. The corresponding `auto` passes use in-house recovery.

```sh
disrobe jvm decompile app.apk --backend jadx --out src/
disrobe dotnet decompile App.dll --backend ilspy --out src/
```

### Native executables and Go

Unpack an executable or recover symbols and Go runtime metadata:

```sh
disrobe native unpack packed.exe --out unpacked.bin
disrobe native symbols app.exe --out symbols.json
disrobe go recover app --out symbols.json
disrobe catalog native
```

For source recovery and architecture limits, see the [native decompiler](./languages/native-decompile.md). A symbol report and recovered function bodies answer different questions; inspect the artifact the selected command actually emits.

### Mobile runtimes and other bytecode

Recover the supported source or structural view for the input:

```sh
disrobe hermes decompile index.android.bundle --out surface/
disrobe flutter dump libapp.so --out layout.json
disrobe lua decompile script.luac --out script.lua
disrobe ruby decompile app.rb
disrobe php decode payload.php --out out/payload-php/
disrobe beam parse module.beam
```

Use the catalog to inspect each family's Recover, Partial, or Detect-only support tier:

```sh
disrobe catalog python
```

## Extract indicators from recovered files

`frisk` scans local files offline for secrets, endpoints, and indicators, with source locations:

```sh
disrobe frisk recovered/ --format json > frisk.json
```

Network enrichment is a separate step. `prowl` queries the selected public archives and feeds for a domain or URL; use a target you intend to disclose to those providers. `indicators` merges the local and network reports and can print a deduplicated target list:

```sh
disrobe prowl example.com --subs --sources wayback,urlscan,crtsh --format json > prowl.json
disrobe indicators frisk.json prowl.json --targets-only > targets.txt
```

Secret values remain visible by default in recon reports. See [recon, redaction, and indicators](./frisk.md) before sharing them.

## Structured output

The global `--json`, `--ndjson`, and `--sarif` flags select machine-readable output where a command supports those formats. For example, `scan` can emit SARIF 2.1.0 for GitHub code scanning:

```sh
disrobe scan firmware.bin --sarif > findings.sarif
```

## Inspecting a run

To revisit a chain run without rerunning recovery:

```sh
disrobe context --out recovered/
```

If a stage failed, use its reported `DR-` error code with `disrobe explain`. A registered entry describes the cause and the input or prerequisite that may resolve it. [Reading a result](./reading-a-result.md) also covers stalls, caps, cycles, and verification failures.

If you created or received a `.dr` envelope, inspect its metadata and verify its integrity separately:

```sh
disrobe envelope inspect module.dr
disrobe verify module.dr
```

## Generating a metadata sidecar

Commands that implement metadata bundles accept `--metadata-pack-1` through `--metadata-pack-4`. `--llm` is a compatibility alias for pack 4; it does not run a model.

```sh
disrobe py decompile module.pyc --out recovered/ --metadata-pack-4 --llm-briefs
```

See [metadata sidecar and provenance](./llm-sidecar.md) for the full category and pack model.
