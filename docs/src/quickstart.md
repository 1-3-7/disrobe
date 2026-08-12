# Quickstart

The fastest path is `disrobe auto`: hand it a file and it fingerprints the input, then chains the right passes end to end.

## Auto-detect and chain

```sh
disrobe auto suspect.exe --out recovered/ --capture-stages
disrobe context --out recovered/
disrobe catalog native
```

`context` summarizes the passes that ran, their confidence tiers, the final verdict, and provenance. It does not replace `recovery.json`; use that file when another tool needs the complete structured report.

`disrobe auto` understands chains such as:

- `PE -> UPX -> rust-demangle -> symbol recovery`
- `PyInstaller -> PyArmor -> .pyc decompile`
- `APK -> DEX -> Java + manifest`
- `Electron .asar -> unbundle -> source`

Use `--capture-stages` to mirror the exact bytes written by each executed pass under `<out>/NN-<pass>/` and link the terminal stage or stages under `<out>/final/`. These are exact stage records; a decompiler's source output is not a byte-identical copy of the compiled input. Cap the chain depth with `--max-depth` (default 8).

## Per-language one-liners

These commands cover the main direct workflows. Run `disrobe <command> --help` before relying on a backend or emit that is not shown here.

```sh
# Python
disrobe py decompile module.pyc --out recovered/
disrobe py disasm module.pyc --out trace.txt
disrobe py deob obfuscated.py --out clean.py --cleanup
disrobe pyinstaller extract onefile.exe --out out/
disrobe pyarmor unpack protected.py --out out/             # v8/v9 stay static by default
disrobe nuitka extract app.exe --out out/

# JavaScript / TypeScript / WebAssembly
disrobe js deob bundle.min.js --out clean.js
disrobe js unbundle app.bundle.js --out src/
disrobe wasm decompile module.wasm --target rust --out lifted.rs
disrobe webview desktop.exe --out frontend/

# JVM / Android / .NET
disrobe jvm decompile app.apk --backend jadx --out src/
disrobe dotnet decompile App.dll --backend ilspy --out src/

# Native
disrobe native unpack packed.exe --out unpacked.bin
disrobe native symbols app.exe --out symbols.json
disrobe go recover app --out symbols.json

# Recon and catalog
disrobe frisk recovered/ --format json > frisk.json
disrobe prowl example.com --subs --sources wayback,urlscan,crtsh --format json > prowl.json
disrobe indicators frisk.json prowl.json --targets-only > targets.txt
disrobe catalog python

# Mobile / Lua / others
disrobe hermes decompile index.android.bundle --out surface/
disrobe flutter dump libapp.so --out layout.json
disrobe lua decompile script.luac --out script.lua
disrobe ruby decompile app.rb
disrobe php decode payload.php --out out/payload-php/
disrobe beam parse module.beam
```

PyArmor v6/v7 may require the dynamic-hook fallback. That path executes the sample and is disabled unless you add `--allow-dynamic`. Use it only inside an isolated sandbox with no network or sensitive mounts. PyArmor v8/v9 and `--allow-bcc` remain static.

## Structured output

The global `--json`, `--ndjson`, and `--sarif` flags select machine-readable output where a command supports those formats. For example, `scan` can emit SARIF 2.1.0 for GitHub code scanning:

```sh
disrobe scan firmware.bin --sarif > findings.sarif
```

## Inspecting a run

After any chain or pass, inspect what landed:

```sh
disrobe status                    # per-stage artifact counts, sizes, manifests in ./out/
disrobe context --out recovered/  # per-pass status, confidence tiers, verdict, provenance
disrobe envelope inspect out/final/module.dr
disrobe verify out/final/module.dr
```

## Generating a metadata sidecar

Commands that implement metadata bundles accept `--metadata-pack-1` through `--metadata-pack-4`. `--llm` is a compatibility alias for pack 4; it does not run a model.

```sh
disrobe py decompile module.pyc --out recovered/ --metadata-pack-4 --llm-briefs
```

See [metadata sidecar and provenance](./llm-sidecar.md) for the full category and pack model.
