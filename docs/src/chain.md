# The chain runner

The chain runner detects each artifact, runs a matching recovery pass, and routes its output to the next pass. It backs both `disrobe auto` (automatic selection) and `disrobe chain` (an explicit pipeline).

## Auto-detection

```sh
disrobe auto suspect.exe --out recovered/
disrobe auto suspect.exe --out shareable/ --redact
```

`disrobe auto` fingerprints the input, picks the highest-confidence pass, runs it, then re-fingerprints the output and repeats until no further pass clears the confidence threshold or the depth cap is hit. `disrobe passes` prints the auto-chain pass IDs compiled into the current binary, with each pass ecosystem and support tier. Use that output instead of a copied count. Direct commands such as `scan`, `frisk`, `taint`, and `webview` are separate surfaces and do not become auto-chain passes merely because the CLI can run them. See [Pass selection](./passes.md#pass-selection) for exactly how the next pass is chosen.

`--redact` replaces secret values in machine output, printed paths and messages, the generated reports (`chain.json`, `recovery.json`, `anti-analysis.json`, `report.json`, `report.sarif`, and `run.json`), and every extracted file that looks like JSON: a `.json` name, or content that starts with `{` or `[` after an optional byte-order mark and whitespace. The values come from a recon scan of the input and of every extracted file, from the secret values listed in extracted `recon.json`, secret-scan, and mobile reports, and from a rescan of each document. An extracted JSON file that contains a secret is rewritten as indented JSON; one that does not parse, or exceeds the redactor's depth, node, or string limits, has its text scrubbed instead; one larger than 64 MiB is not written, and a `DR-CLI-0366` line on stderr names it. Other recovered source, extracted binaries, and the raw stage copies that `--capture-stages` writes are not altered. `disrobe chain` applies the same redaction when `.disrobe.toml` sets `output.redact = true`. Raw report values remain the default.

Representative routes include `native.packer-unpack -> go.classify` for a UPX-packed Go executable and `pyinstaller.extract -> pyarmor.unpack -> py.decompile` when the extracted Python wrapper and available runtime/key material support those stages. APKs reach `jvm.classify`; Electron ASAR archives reach `webview.carve`, whose recognized JavaScript children can continue through `js.deob`. See the [quickstart route table](quickstart.md#auto-detect-and-chain) for their outputs and [registered passes](passes.md#commands-and-auto-chain-passes) for the complete list.

## Explicit chains

When you want to pin the pipeline rather than auto-detect:

```sh
disrobe chain input.bin --chain 'pyarmor.unpack,py.decompile' --out recovered/
disrobe chain input.bin --chain 'auto:8' --out recovered/        # auto-detect, depth 8
disrobe chain input.bin --chain 'auto:8' --chain-pin pyarmor.unpack --out recovered/
```

Explicit chains use comma-separated pass IDs from `disrobe passes`. With `--chain auto[:N]`, `--chain-pin` fixes a pass prefix before automatic selection continues; it does not select package versions.

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

## Output layout

`auto` and `chain` write into the `--out` directory:

```text
out/
├── extracted/
│   ├── lib/app.dll          # a fan-out member, at its path inside the container
│   └── recovered/
│       ├── app.py           # recovered source, named after its input with the language's extension
│       └── chain-node-4.cs  # a source whose input had no name
├── chain.json
└── recovery.json
```

- **Recovered source.** Every stage that ends a branch with recovered source writes it under `extracted/recovered/`. The file keeps the directory and stem of the member it came from, and takes the extension of its language: `.py` for Python, `.cs` for C#, `.java` for Java, `.m` for Objective-C and MATLAB. A source whose input had no name is written as `chain-node-<id>`.
- **Existing output.** `--out` must be empty or absent. A directory that already holds files is refused with `DR-CLI-0913`, because the new run's reports would cite files the run did not write. `--force` accepts such a directory and first deletes the earlier run's `extracted/`. `DR-CLI-0912` reports a directory that cannot be read or cleared.
- **Batch runs.** A directory run gives each input its own output directory, named after the input's relative path. Inputs whose names would give the same directory get numbered suffixes (`app-1`, `app-2`), so no two inputs share one.

## Verdicts

Every node in `chain.json` carries a verdict, and the run carries one overall verdict computed from the branches that end in a leaf.

| Verdict | Meaning | Grade |
| --- | --- | --- |
| `complete` | every counted branch ends in recovered source; the formats are listed | ok |
| `extracted` | a container was opened and its members written, and no pass claims any member | ok |
| `not-applicable` | no pass claims the input, or the only claiming pass found nothing to reverse and returned the input unchanged; nothing is written as recovered | ok |
| `fan-out-partial` | some branches ended in recovered source and others did not | incomplete |
| `stalled` | a pass produced bytes that no further pass claims, or produced nothing | incomplete |
| `cycle`, `cap-reached` | the branch repeated an artifact or hit the depth or output cap | incomplete |
| `error` | every counted branch failed; a container that opens with no members is an error, not an empty success | failed |

A member of a container that no pass claims is `not-applicable` on its own node and does not count against the run: a ZIP holding one `.pyc` and a README is `complete` once the `.pyc` decompiles. A directory run classifies each file from its verdict as recovered (grade ok), incomplete, not applicable or failed, and `manifest.json` counts each class.

## Stage mirrors

Pass `--capture-stages` to materialize the exact bytes written by every executed pass. This records each stage faithfully; it does not mean decompiled source is byte-identical to the compiled input.

```text
recovered/
├── 01-pyinstaller/        # exact recorded output of pass 1
├── 02-pyarmor/            # exact recorded output of pass 2
├── 03-py-decompile/       # exact recorded output of pass 3
├── final/                 # terminal stage(s), linked
│   └── 03-py-decompile/   # symlink, or a recursive copy when symlinks are unavailable
├── chain.json             # the chain topology descriptor
└── recovery.json          # per-pass status and confidence histogram
```

The `final/` link prefers a symlink and falls back to a recursive copy, so `final/` always resolves to the terminal artifact regardless of platform and privilege. On Windows without the symlink privilege or Developer Mode, `final/` is a copy.

## chain.json: the topology descriptor

`chain.json` records the executed pipeline: each pass, its version, the input and output BLAKE3 hashes, the rung transition, byte sizes, and the per-stage verdict. It is the document `disrobe diff` and `disrobe guard verify` operate on (see [Diff and guard tooling](./cli/diff-guard.md)).

Each node includes a `metadata` object whose keys and values are strings. The object is empty when the stage has no metadata. Registered keys use lowercase dotted namespaces. Serialized keys remain in deterministic lexical order.

`anti.recovered_techniques` is a published metadata key. Its value is a nonempty comma-separated list of technique labels with no empty elements, embedded commas, or whitespace around delimiters. The encoded value is limited to 4,096 UTF-8 bytes. An absent key means that the stage reported no recovered technique metadata. An empty or malformed value is an error, not an absent value. The CLI reports malformed metadata as `DR-CLI-0299` before it derives anti-analysis evidence or writes the final chain output.

## recovery.json: the provenance sidecar

`recovery.json` is the per-run report: each pass's status and a confidence-tier histogram. Summarize it without reading raw JSON:

```sh
disrobe context --out recovered/
```

## run.json: timings on request

`chain.json`, `recovery.json`, `report.json`, and `report.sarif` record no duration, no worker count, and no clock, so two runs over one input write identical bytes. Pass `--timings` to `auto` or `chain` to also write `run.json` (schema `disrobe.run/v1`): the start and end clocks, the worker count, the tool version, the run's duration, and each node's duration in milliseconds keyed by node id. Node 0, the input, covers the whole run; a node that ran a pass holds that pass's run time; any other node holds the time spent on it. `disrobe context` prints `run.json` when the directory holds one.

This prints per-pass status, confidence tiers, the overall verdict, and provenance, which is the human-facing view of what the chain actually managed to recover and how much to trust it.
