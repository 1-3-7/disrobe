# GitHub Action

`disrobe` ships a composite [GitHub Action](https://github.com/1-3-7/disrobe) that downloads the matching release binary, runs a scan over a path or glob, and uploads the result to GitHub code scanning as SARIF. It runs entirely in the runner shell (no Docker image, no build step) so it starts in seconds.

## Quick start

Add a workflow that scans build artifacts on every push and surfaces findings in the **Security -> Code scanning** tab.

```yaml
name: disrobe-scan
on:
  push:
  pull_request:

permissions:
  contents: read
  security-events: write   # required for the SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: 1-3-7/disrobe@v0.10.4
        with:
          path: dist/
          command: auto
          fail-on: failed
```

The `security-events: write` permission is what lets the action publish SARIF to code scanning; without it the upload step is skipped by GitHub.

## What it does

1. Resolves the runner OS/arch to a release target triple (`x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, and the rest of the [release matrix](../installation.md)).
2. Downloads `disrobe-<version>-<target>.tar.zst` (or `.zip` on Windows) plus `SHA256SUMS` from this repository's Releases, and **verifies the archive against `SHA256SUMS` before extracting**. A checksum mismatch fails the step.
3. Runs `disrobe <command> <path> <args> --sarif --out <out-dir>`, capturing the SARIF document.
4. Uploads the SARIF to code scanning and the recovered-artifact directory as a workflow artifact.

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | *(required)* | File, directory, or glob to analyze. Passed verbatim to the command. |
| `command` | `auto` | `disrobe` subcommand (`auto`, `scan`, `behavior`, ...). |
| `args` | `""` | Extra arguments inserted after the command and before the path (for example `--max-depth 12`). |
| `version` | action ref, then `latest` | Release tag to download (`v0.10.4`, `latest`). |
| `fail-on` | `never` | Fail the step at or above a verdict: `never`, `incomplete`, `failed`, `any`. |
| `sarif-file` | `disrobe.sarif` | Path the action writes the SARIF to. |
| `out-dir` | `disrobe-out` | Directory `disrobe` writes recovered artifacts into. |
| `upload-sarif` | `true` | Upload SARIF to GitHub code scanning. |
| `upload-artifact` | `true` | Upload the recovered-artifact directory. |
| `token` | `${{ github.token }}` | Token used to download the release asset. |

## Outputs

| Output | Description |
|---|---|
| `sarif` | Path to the SARIF file the action produced. |
| `verdict` | Worst verdict observed (`ok`, `incomplete`, `failed`). |
| `summary` | One-line human-readable run summary. |

## Pinning the version

Pin a tag for reproducible CI:

```yaml
      - uses: 1-3-7/disrobe@v0.10.4
        with:
          path: suspect.bin
          version: v0.10.4
```

Leaving `version` unset downloads the release matching the action ref, falling back to the rolling `latest` release. Pin a tag in production so a new release cannot change your scan results silently.

## Gating a pull request

Block a merge when a packed or obfuscated artifact slips into the tree:

```yaml
      - uses: 1-3-7/disrobe@v0.10.4
        with:
          path: "build/**/*"
          command: auto
          args: --max-depth 12
          fail-on: failed
```

`fail-on: failed` fails only when the chain itself errors; `fail-on: incomplete` is stricter and also fails when `disrobe` reports findings it could not fully resolve. The action reports what `disrobe` detects; it does not invent verdicts.

## Security posture

The action verifies every download against `SHA256SUMS` before extracting it, and every release archive additionally carries a [cosign](https://github.com/sigstore/cosign) signature bundle you can verify out of band. `disrobe` itself performs pure static analysis by default; see the [forensics and malware-safety posture](../forensics-safety.md).
