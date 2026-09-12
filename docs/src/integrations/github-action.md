# GitHub Action

`disrobe` ships a composite [GitHub Action](https://github.com/1-3-7/disrobe) that downloads the matching release binary, runs the selected command against one path, validates the emitted SARIF, and uploads that report to GitHub code scanning. It runs in the runner shell without a Docker image or source build.

The [recorded local example](https://github.com/1-3-7/disrobe/blob/main/docs/demo/github-action.json) runs the Action's `detect` and `auto` steps against the 69-byte WebAssembly fixture. It includes the emitted SARIF, step outputs and recovery grade. Reproduce it with [capture-action.mjs](https://github.com/1-3-7/disrobe/blob/main/docs/demo/capture-action.mjs).

## Quick start

Add a workflow that scans build artifacts on every push and surfaces findings in the **Security -> Code scanning** tab.

```yaml
name: disrobe-scan
on:
  push:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: 1-3-7/disrobe@v0.10.6
        with:
          path: dist/
          command: auto
          fail-on: failed
```

The `security-events: write` permission lets the upload step publish SARIF to code scanning. A workflow without that permission must set `upload-sarif: false` or the upload step will fail.

## What it does

1. Resolves the runner OS/arch to a release target triple (`x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, and the rest of the [release matrix](../installation.md)).
2. Downloads `disrobe-<version>-<target>.tar.zst` (or `.zip` on Windows) plus `SHA256SUMS` from this repository's Releases, and **verifies the archive against `SHA256SUMS` before extracting**. A checksum mismatch fails the step.
3. Runs `disrobe <command> <args> <path> --sarif --out <out-dir>`, capturing the SARIF document.
4. Rejects a failed analyzer process or missing, malformed, or non-Disrobe SARIF output.
5. Uploads validated SARIF to code scanning and the recovered-artifact directory as a workflow artifact.

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | *(required)* | One file or directory path to analyze. Passed as one argument without shell expansion. |
| `command` | `auto` | `disrobe` subcommand (`auto`, `scan`, `behavior`, ...). |
| `args` | `""` | Extra arguments inserted after the command and before the path (for example `--max-depth 12`). |
| `version` | action ref, then `latest` | Release tag to download (`v0.10.6`, `latest`). |
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
      - uses: 1-3-7/disrobe@v0.10.6
        with:
          path: suspect.bin
          version: v0.10.6
```

Leaving `version` unset downloads the release matching the action ref, falling back to the rolling `latest` release. Pin a tag in production so a new release cannot change your scan results silently.

## Gating recovery failures

Fail the step when recovery is incomplete or fails:

```yaml
      - uses: 1-3-7/disrobe@v0.10.6
        with:
          path: build/
          command: auto
          args: --max-depth 12
          fail-on: incomplete
```

`fail-on: failed` rejects failed recovery reports. `fail-on: incomplete` and `fail-on: any` also reject incomplete recovery reports. These thresholds grade the chain recovery verdict; a SARIF finding or a detected packed format does not by itself cross the threshold. Use code-scanning rules when a pull request must be blocked on selected findings. Analyzer execution errors and invalid SARIF always fail the Action, regardless of `fail-on`.

When `fail-on` rejects a valid recovery report, the Action still uploads its validated SARIF before returning the failed result. Analyzer errors and invalid SARIF do not produce an upload path.

## Security posture

The action verifies every download against `SHA256SUMS` before extracting it, and every release archive additionally carries a [cosign](https://github.com/sigstore/cosign) signature bundle you can verify out of band. `disrobe` itself performs pure static analysis by default; see the [forensics and malware-safety posture](../forensics-safety.md).
