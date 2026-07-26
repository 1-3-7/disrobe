# Run reports (`disrobe report`)

`disrobe report` consolidates a completed run into a single forensic summary: input identity, chain topology, per-stage verdicts and recovery scores, the recovered-artifact inventory, and timings. It is the read-side companion to `auto` and `chain`.

## Usage

```bash
disrobe report ./out/sample-auto                 # a completed single-file run
disrobe report ./out/samples-batch               # a completed batch run
disrobe report ./malware.bin                     # raw input: runs auto first, then reports
disrobe report ./out/sample-auto --format markdown
disrobe report ./out/sample-auto --format html > report.html   # self-contained, offline
```

## Target resolution

The single positional argument can be:

| Target | Behavior |
|---|---|
| A directory with `manifest.json` | Read it and render a **batch** report. |
| A directory with `chain.json` + `recovery.json` | Read them and render a **single-run** report. |
| A raw input **file** | Run `auto` into `./out/<stem>-auto/` first, then report. |
| A raw **directory** (not an out dir) | Run a batch into `./out/<dir>-batch/` first, then report. |

A non-existent target is a hard error (`DR-CLI-0350`).

## Formats

`--format text|json|markdown|html` (default `text`). The global `--json` flag forces JSON regardless of `--format`.

- `text`: an aligned human report for the terminal.
- `markdown`: a report with tables, ready to paste into an issue or PR.
- `json`: the machine-readable `disrobe.report/v1` document.
- `html`: a single self-contained HTML file (printed to stdout; redirect to a `.html`). CSS is inlined from the shared docs theme token file, with no JavaScript and no external/CDN reference, so it renders offline when double-clicked. Sections include input identity, a chain-topology flow, per-stage verdicts with generated recovery bars, a generated tier histogram, recovered artifacts, and, when the input is still readable, defanged IOC plus behavior / MITRE ATT&CK tables. Every interpolated value is HTML-escaped, and the renderer uses no clock or randomness, so identical report data produces byte-stable HTML.

### Single-run report contents

- Input identity: path, size, BLAKE3, detected format chain, final format.
- Topology and verdict: linear or tree, and the overall chain verdict.
- Recovery score: the mean per-stage confidence-tier rank normalized to `[0, 1]`, plus a tier label (skeleton / partial / semantic / exact).
- Tier histogram: exact / semantic / partial / skeleton counts.
- Per-stage table: index, pass id, confidence, score, duration.
- Recovered-artifact inventory: the union of artifact names produced by the stages.
- Notes: detect-only and skeleton-tier caveats.

### Batch report contents

- The aggregate counts (`processed`, `recovered`, `detect-only`, `errors`) and mean recovery score.
- A per-file table: file, detected format, score, and status (recovered / detect-only / error).
