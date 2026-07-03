# Quickstart

The fastest path is `disrobe auto`: hand it a file and it fingerprints the input, then chains the right passes end to end.

## Auto-detect and chain

```sh
disrobe auto suspect.exe --out recovered/
disrobe catalog native
```

```text
# detected: PE -> UPX -> rust-demangle
# stage 01-upx        ok    (.text byte-identical, 1.18 MiB in 9 ms)
# stage 02-demangle   ok    (4172 Rust symbols, 312 C++ symbols, 0 unresolved)
# final               ok    -> recovered/final/
```

`disrobe auto` understands chains such as:

- `PE -> UPX -> rust-demangle -> symbol recovery`
- `PyInstaller -> PyArmor -> .pyc decompile`
- `APK -> dex -> JADX + Smali + manifest`
- `Electron .asar -> unbundle -> source`

Use `--capture-stages` to mirror every executed pass's byte-exact output under `<out>/NN-<pass>/` and link the terminal stage(s) under `<out>/final/`. Cap the chain depth with `--max-depth` (default 8).

## Per-language one-liners

Every one of these is real and backed by an in-tree fixture and integration test:

```sh
# Python
disrobe py decompile module.pyc --out recovered/
disrobe py disasm module.pyc --out trace.txt
disrobe py deob obfuscated.py --out clean.py --cleanup
disrobe pyinstaller extract onefile.exe --out out/
disrobe pyarmor unpack protected.py --out out/             # add --allow-dynamic only on trusted samples
disrobe nuitka extract app.exe --out out/

# JavaScript / TypeScript / WebAssembly
disrobe js deob bundle.min.js --out clean.js
disrobe js unbundle app.bundle.js --out src/
disrobe wasm decompile module.wasm --target rust --out lifted.rs

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

## Structured output

Every command accepts the global `--json`, `--ndjson`, or `--sarif` flags for machine-readable output. SARIF 2.1.0 drops straight into GitHub code scanning:

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

Add `--metadata-pack-4` to any pass to emit a schema-conforming metadata bundle next to the recovered artifact:

```sh
disrobe py decompile module.pyc --out recovered/ --metadata-pack-4 --llm-briefs
```

See [metadata sidecar and provenance](./llm-sidecar.md) for the full category and pack model.
