# Run reports (`disrobe report`)

`disrobe report` consolidates a completed run into a single forensic summary: input identity, chain topology, per-stage verdicts and recovery scores, the layers that stopped short, the recovered-artifact inventory, a cited byte range and digest for every artifact the run read, the steps that re-check each one, and timings. It is the read-side companion to `auto` and `chain`.

## Usage

```bash
disrobe report ./out/sample-auto                 # a completed single-file run
disrobe report ./out/samples-batch               # a completed batch run
disrobe report ./malware.bin                     # raw input: runs auto first, then reports
disrobe report ./out/sample-auto --format markdown
disrobe report ./out/sample-auto --format html > report.html    # self-contained, offline
disrobe report ./out/sample-auto --format sarif > report.sarif
```

`--out <DIR>` chooses where a derived run is written when the target is a raw input or a raw directory. Without it the derived run lands in `./out/<stem>-auto/` or `./out/<name>-batch/` under the working directory. The flag has no effect when the target is already a completed run.

## Target resolution

The single positional argument can be:

| Target | Behavior |
|---|---|
| A directory with `manifest.json` | Read it and render a **batch** report. |
| A directory with `chain.json` + `recovery.json` | Read them and render a **single-run** report. |
| A raw input **file** | Run `auto` into `./out/<stem>-auto/` first, then report. |
| A raw **directory** (not an out dir) | Run a batch into `./out/<dir>-batch/` first, then report. |

A run document that is missing, unreadable, or truncated stops the command with a typed error. Nothing is partly rendered.

| Condition | Code |
|---|---|
| The target path does not exist | `DR-CLI-0350` |
| `chain.json` cannot be read | `DR-CLI-0351` |
| `chain.json` is not a valid chain document | `DR-CLI-0352` |
| `recovery.json` cannot be read | `DR-CLI-0353` |
| `recovery.json` is not a valid recovery document | `DR-CLI-0354` |
| `manifest.json` cannot be read | `DR-CLI-0355` |
| `manifest.json` is not a valid batch manifest | `DR-CLI-0356` |
| A raw input file cannot be read | `DR-CLI-0358` |

## The report a run writes

`disrobe auto` and `disrobe chain` write `report.json` into the output directory, beside `chain.json`, `recovery.json`, and `anti-analysis.json`. It holds the single-run document described below, so a run is citable without a second command. The document `auto` writes and the document `disrobe report <out-dir> --format json` prints are the same, except that the command's JSON adds a `report_kind` discriminator.

A batch run writes an aggregate `report.json` beside `manifest.json`; it is the same JSON document that `disrobe report <batch-out> --format json` prints. Each file also leaves its own single-run `report.json` in its per-file output directory.

## Formats

`--format text|json|markdown|html|sarif` (default `text`). A global machine-output flag (`--json`, `--ndjson`, or `--sarif`) forces JSON output. `--format sarif` overrides that and renders SARIF.

- `text`: an aligned human report for the terminal.
- `markdown`: a report with tables, ready to paste into an issue or PR.
- `json`: the machine-readable `disrobe.report/v1` document.
- `html`: a single self-contained HTML file (printed to stdout; redirect to a `.html`). CSS is inlined from the shared docs theme token file, with no JavaScript and no external/CDN reference, so it renders offline when double-clicked. Sections include input identity, a chain-topology flow, per-stage verdicts with generated recovery bars, a generated tier histogram, walls and failures, capabilities, recovered artifacts, the evidence table, the reproduction steps, and, when the input is still readable, defanged IOC plus behavior / MITRE ATT&CK tables. Every interpolated value is HTML-escaped, and the renderer uses no clock or randomness, so identical report data produces byte-stable HTML.
- `sarif`: a SARIF 2.1.0 log printed to stdout. See [SARIF output](#sarif-output).

### Single-run report contents

- Input identity: path, size, BLAKE3, detected format chain, final format.
- Topology and verdict: linear or tree, and the overall chain verdict.
- Recovery score: the mean per-stage confidence-tier rank normalized to `[0, 1]`, plus a tier label (skeleton / partial / semantic / exact).
- Tier histogram: exact / semantic / partial / skeleton counts.
- Per-stage table: index, pass id, confidence, score, duration.
- Walls: every layer that stopped short, with the input it lacks.
- Capabilities: ATT&CK- and MBC-tagged rule matches with addresses and evidence scope. Text, JSON, markdown, HTML, and SARIF consume the same result.
- Failures: every layer that returned an error, with its message.
- Recovered-artifact inventory: the union of artifact names produced by the stages.
- Evidence: one cited entry per artifact the report read, with its digest and byte range.
- Reproduction: the command that rebuilds the report and the steps that re-check it.
- Notes: detect-only, skeleton-tier, and artifact-walk truncation caveats.

### Batch report contents

- The aggregate counts (`processed`, `recovered`, `detect-only`, `errors`) and mean recovery score. The mean is null when no file carried a score.
- A per-file table: file, detected format, score, and status (recovered / detect-only / error).

A batch report aggregates per-file manifests and holds no analysis-target bytes. Its SARIF render therefore reports the STIX, MAEC, capability, and indicator blocks as unavailable, each with that reason.

## Walls and failures

A wall is a layer that stopped because a named input is missing. A wall is not a failure and is never rendered as an error. Each wall records its kind, the node id, the stage index when the layer maps to one, the pass, the input format, the BLAKE3 and size of the artifact it could not advance, and a sentence naming what it lacked.

| Kind | The layer stopped because |
|---|---|
| `no-pass-accepted` | No registered detector claimed the artifact. |
| `empty-pass-output` | A pass accepted the format and returned no output bytes. |
| `repeated-artifact` | The output repeats an artifact already seen on the branch. |
| `depth-cap-reached` | The chain reached its depth cap. |
| `not-executed` | The run was a dry run, so the selected pass was never executed. |
| `branches-incomplete` | At least one branch of a fan-out did not reach a recovered format. |

A layer that returned an error is recorded as a failure instead. A failure carries the node id, the stage index when the layer maps to one, the pass, the recorded message, and the BLAKE3 and size of its input.

When no individual node recorded a wall or a failure, the overall chain verdict still produces one wall against the root node if that verdict is stalled, cycle, cap-reached, dry-run, or fan-out-partial. A run that recovered nothing reports the wall rather than an empty success.

## Evidence and digests

Every report cites the artifacts it read. An evidence entry carries a role, an artifact URI, a byte offset, a byte length, a BLAKE3 digest, and where that digest came from.

The roles are `analysis-target`, `stage-input`, `stage-output`, and `recovered-artifact`.

| Digest source | Meaning |
|---|---|
| `chain-document` | The digest is the one `chain.json` recorded, for the analysis target or for a stage input or output. |
| `recomputed-from-file` | `disrobe report` opened the file in the run directory and hashed its bytes. The byte length is the file length. |
| `unavailable` | No digest could be produced. The entry carries an `unavailable_reason` naming why. |

Only recovered artifacts read off disk carry `recomputed-from-file`. An artifact a dry run would have written, a file that is not on disk under the run directory, and a file that cannot be opened are each cited with `unavailable` and a reason rather than dropped from the report.

An artifact on disk is cited by a `file://` URI, or by its percent-encoded relative path when the recorded path is relative. An intermediate the chain held in memory is cited as `ni:///blake3;<digest>`. That names the artifact a byte range indexes; it is not a file you can open.

Every evidence entry starts at byte offset 0 and spans the whole artifact. Sub-ranges inside the analysis target come from the indicator results in the SARIF render.

The recovered-artifact inventory combines the artifact names the stages recorded with the files under `extracted/` in the run directory. That walk skips symbolic links, stops at directory depth 32, and stops after 4096 files. Either stop is recorded as a note in the report, naming what is not cited.

## Reproduction steps

A single-run report carries the command that rebuilds it and the steps a third party follows to re-check it:

1. Hash the analysis target with BLAKE3 and compare it with `input.blake3`.
2. Hash each evidence entry marked `recomputed-from-file` and compare each digest with the recorded one.
3. Read each `ni:///blake3;` evidence entry as the digest of an intermediate the chain held in memory.
4. Re-run the reported command and compare the output.
5. Set `SOURCE_DATE_EPOCH` to make the SARIF `generated_at` field byte-identical too.

When any entry carries no digest, a further step counts those entries and points at their `unavailable_reason`.

## SARIF output

`--format sarif` prints a SARIF 2.1.0 log to stdout. The CLI test suite validates that log against the SARIF 2.1.0 schema vendored under `crates/disrobe-cli/tests/schemas/`.

`run.artifacts` is the artifact table. Each entry carries its URI, a description, the byte length when the report knows it, its SARIF roles, and a `blake3` hash when the report has one. An entry with no digest carries no hash. The roles follow the evidence roles: the analysis target becomes `analysisTarget`, a recovered artifact becomes `resultFile`, and a stage input or output becomes `unmodified`.

Every result location names an artifact URI and its index in `run.artifacts`. A region cites a byte offset and a byte length. A span whose offset plus length would leave the artifact is dropped rather than cited, so a cited range always reads back inside the artifact it indexes.

Results carry one of these rule ids. A rule is declared in `tool.driver.rules` only when the run produced at least one result for it.

| Rule id | One result per |
|---|---|
| `disrobe.stage` | Executed chain layer. |
| `disrobe.wall` | Layer that stopped because a named input is missing. |
| `disrobe.failure` | Layer that returned an error. |
| `disrobe.evidence` | Cited artifact. |
| `disrobe.indicator` | Value read out of the analysis target. |
| `disrobe.behavior` | Behavior category matched in the analysis target. |
| `disrobe.batch-file` | File of a batch run. |

Only two results are reported as `level: error` with `kind: fail`: a failure, and a batch entry whose manifest recorded an error. A wall is `level: none` with `kind: review`, so a layer that stopped short never reaches a code-scanning gate as an error. A behavior is `kind: review`. An evidence entry whose digest is unavailable is `kind: review`. Every other evidence entry, every stage, every indicator, and every batch entry that ran is `kind: informational`.

An indicator result records the offset and length of the value inside the analysis target, and a `range_within_target` flag. When a recorded offset lies outside the target, the result is kept, the flag is false, and the message says the range lies outside the analysis target.

`run.invocations[0].commandLine` holds the reproduction command. `executionSuccessful` is false when a single run recorded a failure, or when a batch manifest recorded an error.

### `run.properties`

| Key | Contents |
|---|---|
| `generated_at` | The one timestamp value the document uses. |
| `disrobe` | The `disrobe.report/v1` document. |
| `stix` | A STIX 2.1 bundle, or `available: false` with a reason. |
| `maec` | A MAEC 5.0 package of behavior objects, or `available: false` with a reason. |
| `capabilities` | The capability report for the analysis target, or `available: false` with a reason. |
| `indicators` | The aggregated indicator bundle, or `available: false` with a reason. |
| `reproduction` | The command and the steps. Single-run reports only. |
| `standards` | The standards this render targets, and the ones it excludes. |

The STIX bundle carries an `identity` object for the tool and a `malware-analysis` object for the run. Its `result` field stays `unknown`, because disrobe performs static recovery and does not classify a sample. Identifiers are derived from the first 16 bytes of BLAKE3 over a stable seed, stamped with the RFC 9562 version 4 and variant bits, so repeated runs over one input produce one identifier.

URL, domain, IPv4, IPv6, email, and registry indicators become STIX indicator objects. Hash, ASN, wallet, path, secret, and other indicators have no STIX pattern object path. They are counted by class in `standards.stix.unmapped_indicator_classes` and stay in the SARIF results only.

The `standards` block records SARIF 2.1.0, STIX 2.1, MAEC 5.0, and CycloneDX 1.5, and names OpenIOC 1.1 and CybOX 2.x as excluded with a reason for each.

### What the enriched blocks need

The STIX, MAEC, capability, and indicator blocks read the original analysis target. The report opens it at the path `chain.json` recorded, resolved against the working directory. Capability analysis is limited to 256 MiB and verifies the bytes against the recorded BLAKE3 before attaching results. If the chain document records no path, the sample has moved or changed, the target exceeds the limit, or you run the command from another directory, the affected block reports `available: false` and names the reason. The rest of the report still renders.

## Determinism

Text, JSON, markdown, and HTML output is byte-identical across runs over one target.

`generated_at` is the only wall-clock field in the SARIF render, and every timestamp in that document holds its value. Two SARIF renders over one target therefore differ only in that value. Set `SOURCE_DATE_EPOCH` to a Unix timestamp to fix it. The SARIF render is then byte-identical too, and `standards.timestamp.source` reads `source-date-epoch` instead of `system-clock`.
