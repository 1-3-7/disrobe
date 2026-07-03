# pre-commit hook

`disrobe` ships a [pre-commit.com](https://pre-commit.com) hook that scans staged files and **fails the commit when a packed or protected artifact is detected**. Use it to stop someone from accidentally (or maliciously) committing a UPX-packed binary, a PyArmor-protected module, a PyInstaller one-file build, or a SourceDefender/Nuitka/PyFreeze blob.

## Setup

Add the hook to a consuming project's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/1-3-7/disrobe
    rev: v0.10.0
    hooks:
      - id: disrobe
```

Then install it:

```sh
pre-commit install
```

The hook requires the `disrobe` binary on `PATH` (install from the [Releases page](../installation.md)), or point it at an explicit path with the `DISROBE_BIN` environment variable. It also needs `python3` available to parse the chain report.

## What it detects

For each staged file the hook runs `disrobe auto <file> --json` against a throwaway output directory and inspects the chain's chosen detector picks. By default it blocks only the **high-precision packer/protector detectors**, which key off unambiguous structural magic and do not false-positive on ordinary source:

| Detector pass | Blocks |
|---|---|
| `native.packer-unpack` | UPX, Petite, kkrunchy, and other native packers |
| `pyarmor.unpack` | PyArmor-protected Python |
| `pyinstaller.extract` | PyInstaller one-file / one-dir builds |
| `sourcedefender.decrypt` | SourceDefender-encrypted Python |
| `nuitka.extract` | Nuitka-compiled binaries |
| `pyfreeze.extract` | Frozen-Python blobs |

This is deliberately conservative: it blocks exactly the formats above, nothing more.

## Tuning

Two environment variables tune the gate:

| Variable | Default | Effect |
|---|---|---|
| `DISROBE_BIN` | `disrobe` | Path to the `disrobe` binary. |
| `DISROBE_BLOCK_PASSES` | the six passes above | Comma-separated detector pass-ids to block. |
| `DISROBE_BLOCK_FAMILIES` | *(empty)* | Comma-separated detector **families** to additionally block. |

The family override is broader but noisier. `disrobe`'s source-level obfuscation classifiers (`js.deob`, `lua.deob`, `py.deob`) are tuned to *attempt* recovery aggressively, so they can fire at high confidence on ordinary text and markdown. Enabling `DISROBE_BLOCK_FAMILIES=obfuscator-wrapper,packer-archive` will catch source-level obfuscation but expect false positives on benign files; scope it with the hook's `files:`/`exclude:` patterns.

```yaml
repos:
  - repo: https://github.com/1-3-7/disrobe
    rev: v0.10.0
    hooks:
      - id: disrobe
        files: '\.(exe|dll|so|dylib|pyc|pyz|bin)$'
```

## Bypassing

A legitimately-committed protected artifact can skip the hook for one commit:

```sh
SKIP=disrobe git commit -m "vendor signed third-party binary"
```

## Security posture

The hook runs `disrobe auto`, which performs pure static analysis by default; it does not execute the staged file. See the [forensics and malware-safety posture](../forensics-safety.md). The scan writes recovered artifacts only into a temporary directory that the hook deletes on exit; your working tree is never modified.
