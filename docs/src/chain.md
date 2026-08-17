# The chain runner

The chain runner is what turns a pile of single-purpose passes into a one-command recovery. It backs both `disrobe auto` (detect and chain automatically) and `disrobe chain` (drive an explicit pipeline).

## Auto-detection

```sh
disrobe auto suspect.exe --out recovered/
disrobe auto suspect.exe --out shareable/ --redact
```

`disrobe auto` fingerprints the input, picks the highest-confidence pass, runs it, then re-fingerprints the output and repeats until no further pass clears the confidence threshold or the depth cap is hit. `disrobe passes` prints the auto-chain pass IDs compiled into the current binary, with each pass ecosystem and support tier. Use that output instead of a copied count. Direct commands such as `scan`, `frisk`, `taint`, and `webview` are separate surfaces and do not become auto-chain passes merely because the CLI can run them. See [Pass selection](./passes.md#pass-selection) for exactly how the next pass is chosen.

`--redact` replaces detected secret values in machine output and the generated JSON reports. It does not alter recovered source or extracted binary artifacts. Raw report values remain the default.

Representative chains:

- `PE -> UPX -> rust-demangle`
- `PyInstaller -> PyArmor -> .pyc decompile`
- `APK -> DEX -> Java + manifest`
- `Electron .asar -> unbundle -> source`

## Explicit chains

When you want to pin the pipeline rather than auto-detect:

```sh
disrobe chain input.bin --chain 'pyarmor+py-decompile' --out recovered/
disrobe chain input.bin --chain 'auto:8' --out recovered/        # auto-detect, depth 8
disrobe chain input.bin --chain 'pyarmor+py-decompile' --chain-pin pyarmor@0.10.0,py-decompile@0.10.0
```

`--chain-pin` locks each pass to a specific version so a recovery is reproducible against an exact pass build.

## Layered payload recovery

`disrobe` unwraps obfuscated and packed payloads recursively. A structural check gates every step (compression magic, a loadable marshal object, a valid parse, a validated crib), so a decode never advances on garbage, and every decompression is bomb-bounded.

| Layer | What it reverses |
|---|---|
| Recursive peel | Stacked encoding and compression down to the real payload. The Python engine unwinds base64/85/32/16, zlib/gzip/bz2/xz/lzma, pyc-strip, marshal, and cipher layers (depth-capped, bomb-bounded); PHP, JavaScript (`atob` chains), and shell have their own recursive peelers; and the chain driver re-detects and re-routes every carved child, so stacked containers across any ecosystem peel end-to-end |
| Marshaled Python code objects | A raw CPython marshal blob (1.0 through 3.15) is loaded, its nested code objects (up to 64 deep) recovered, and each layer decompiled to source |
| Encoding and cipher reversal | base64/85/32/16, base58/62/45/91/92/122, ascii85/Z85, uuencode/xxencode/yEnc, percent-URL, HTML entity, and Punycode, plus gzip/zlib/xz/lzma/bz2 and rot-N. Keyed layers (XOR single and repeating-key, RC4, TEA/XTEA/XXTEA, ChaCha20, Salsa20) are recovered when the key is a literal, a crib, or brute-forceable; custom and shuffled base64 alphabets are sniffed from cribs. A blind cascade keeps only decodes a structural validator accepts; runtime-only-key crypto is stated as a wall, not guessed |
| Per-language loader unwrap | Python `exec`/`eval`/`compile`, PHP `eval`/`assert`/`preg_replace`-e/`create_function`, JavaScript `eval`/`Function` indirection plus esoteric encoders (JSFuck, the Dean Edwards packer, JJEncode, AAEncode) and V8 bytenode/SEA/asar carving, Lua per-obfuscator string and VM recovery, and PowerShell and bash Invoke-Obfuscation families |

## Depth and cycle safety

Adversarial input can try to make a chain recurse forever (an archive nested inside itself, a packer that re-emits its own signature). The chain runner defends against this:

- **Depth cap.** `--max-depth` (default 8) bounds how many passes can run in one chain.
- **Cycle detection.** Each stage's output is content-hashed (BLAKE3); if a stage produces bytes already seen earlier in the chain, the runner stops rather than looping.

## Stage mirrors

Pass `--capture-stages` to materialize the exact bytes written by every executed pass. This records each stage faithfully; it does not mean decompiled source is byte-identical to the compiled input.

```text
recovered/
├── 01-pyinstaller/        # exact recorded output of pass 1
├── 02-pyarmor/            # exact recorded output of pass 2
├── 03-py-decompile/       # exact recorded output of pass 3
├── final/                 # terminal stage(s), linked
│   └── 03-py-decompile/   # symlink -> NTFS junction -> recursive copy fallback (Windows)
├── chain.json             # the chain topology descriptor
└── recovery.json          # per-pass status, confidence histogram, timings
```

The `final/` link prefers a symlink, falls back to an NTFS junction on Windows, and finally to a recursive copy, so `final/` always resolves to the terminal artifact regardless of platform and privilege.

## chain.json: the topology descriptor

`chain.json` records the executed pipeline: each pass, its version, the input and output BLAKE3 hashes, the rung transition, byte sizes, and the per-stage verdict. It is the document `disrobe diff` and `disrobe guard verify` operate on (see [Diff and guard tooling](./cli/diff-guard.md)).

Each node includes a `metadata` object whose keys and values are strings. The object is empty when the stage has no metadata. Registered keys use lowercase dotted namespaces. Serialized keys remain in deterministic lexical order.

`anti.recovered_techniques` is a published metadata key. Its value is a nonempty comma-separated list of technique labels with no empty elements, embedded commas, or whitespace around delimiters. The encoded value is limited to 4,096 UTF-8 bytes. An absent key means that the stage reported no recovered technique metadata. An empty or malformed value is an error, not an absent value. The CLI reports malformed metadata as `DR-CLI-0299` before it derives anti-analysis evidence or writes the final chain output.

## recovery.json: the provenance sidecar

`recovery.json` is the per-run report: each pass's status, a confidence-tier histogram, and timings. Summarize it without reading raw JSON:

```sh
disrobe context --out recovered/
```

This prints per-pass status, confidence tiers, the overall verdict, and provenance, which is the human-facing view of what the chain actually managed to recover and how much to trust it.
