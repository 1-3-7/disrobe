# The chain runner

The chain runner is what turns a pile of single-purpose passes into a one-command recovery. It backs both `disrobe auto` (detect and chain automatically) and `disrobe chain` (drive an explicit pipeline).

## Auto-detection

```sh
disrobe auto suspect.exe --out recovered/
```

`disrobe auto` fingerprints the input, picks the first pass, runs it, then re-fingerprints the output and repeats — following the capability resolver — until no further pass applies or the depth cap is hit. Detection spans 23 pass crates: native packer, PyArmor, JS deob, Python deob, container formats, SourceDefender, py-decompile, py-disasm, PyInstaller, JVM, .NET, Go, mobile, AS3, BEAM, Lua, Ruby, shell, PHP, Nuitka, Wasm, pyfreeze, and swift-objc.

Representative chains:

- `PE -> UPX -> rust-demangle`
- `PyInstaller -> PyArmor -> .pyc decompile`
- `APK -> dex -> JADX + Smali + manifest`
- `Electron .asar -> webcrack -> source`

## Explicit chains

When you want to pin the pipeline rather than auto-detect:

```sh
disrobe chain input.bin --chain 'pyarmor+py-decompile' --out recovered/
disrobe chain input.bin --chain 'auto:8' --out recovered/        # auto-detect, depth 8
disrobe chain input.bin --chain 'pyarmor+py-decompile' --chain-pin pyarmor@0.9.0,py-decompile@0.9.0
```

`--chain-pin` locks each pass to a specific version so a recovery is reproducible against an exact pass build.

## Depth and cycle safety

Adversarial input can try to make a chain recurse forever (an archive nested inside itself, a packer that re-emits its own signature). The chain runner defends against this:

- **Depth cap.** `--max-depth` (default 8) bounds how many passes can run in one chain.
- **Cycle detection.** Each stage's output is content-hashed (BLAKE3); if a stage produces bytes already seen earlier in the chain, the runner stops rather than looping.

## Stage mirrors

Pass `--capture-stages` to materialize every executed pass's byte-exact output:

```text
recovered/
├── 01-pyinstaller/        # byte-exact output of pass 1
├── 02-pyarmor/            # byte-exact output of pass 2
├── 03-py-decompile/       # byte-exact output of pass 3
├── final/                 # terminal stage(s), linked
│   └── 03-py-decompile/   # symlink -> NTFS junction -> recursive copy fallback (Windows)
├── chain.json             # the chain topology descriptor
└── recovery.json          # per-pass status, confidence histogram, timings
```

The `final/` link prefers a symlink, falls back to an NTFS junction on Windows, and finally to a recursive copy — so `final/` always resolves to the terminal artifact regardless of platform and privilege.

## chain.json — the topology descriptor

`chain.json` records the executed pipeline: each pass, its version, the input and output BLAKE3 hashes, the rung transition, byte sizes, and the per-stage verdict. It is the document `disrobe diff` and `disrobe guard verify` operate on (see [Diff and guard tooling](./cli/diff-guard.md)).

## recovery.json — the provenance sidecar

`recovery.json` is the per-run report: each pass's status, a confidence-tier histogram, and timings. Summarize it without reading raw JSON:

```sh
disrobe context --out recovered/
```

This prints per-pass status, confidence tiers, the overall verdict, and provenance, which is the human-facing view of what the chain actually managed to recover and how much to trust it.
