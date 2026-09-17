# pre-commit hook

The [pre-commit](https://pre-commit.com) hook scans staged files and rejects a commit when a configured detector identifies a packed or protected artifact. Analysis errors also reject the commit.

## Setup

Add the hook to a consuming project's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/1-3-7/disrobe
    rev: v0.10.6
    hooks:
      - id: disrobe
```

Then install it:

```sh
pre-commit install
```

The hook requires Bash and the `disrobe` binary on `PATH` (see [installation](../installation.md)), or an explicit Disrobe path in `DISROBE_BIN`. It uses `python3` to parse the chain report. Set `DISROBE_PYTHON` to select another Python 3 executable.

On Windows, use Git Bash or add Git for Windows' `bin` directory to the shell's `PATH`. For a default installation and a project virtual environment:

```powershell
$env:PATH = "C:\Program Files\Git\bin;$env:PATH"
$env:DISROBE_PYTHON = (Resolve-Path .venv/Scripts/python.exe).Path
pre-commit run --all-files
```

## What it detects

For each staged file, the hook runs `disrobe auto <file> --json` with a temporary output directory and checks the chain's chosen detector picks. The default configuration blocks these passes:

| Detector pass | Blocks |
|---|---|
| `native.packer-unpack` | UPX, Petite, kkrunchy, and other native packers |
| `pyarmor.unpack` | PyArmor-protected Python |
| `pyinstaller.extract` | PyInstaller one-file / one-dir builds |
| `sourcedefender.decrypt` | SourceDefender-encrypted Python |
| `nuitka.extract` | Nuitka-compiled binaries |
| `pyfreeze.extract` | Frozen-Python blobs |

Source-level obfuscation detectors are excluded from the default configuration.

## Tuning

Environment variables configure the gate:

| Variable | Default | Effect |
|---|---|---|
| `DISROBE_BIN` | `disrobe` | Path to the `disrobe` binary. |
| `DISROBE_PYTHON` | `python3` | Path to a Python 3 executable. |
| `DISROBE_BLOCK_PASSES` | the six passes above | Comma-separated detector pass-ids to block. |
| `DISROBE_BLOCK_FAMILIES` | *(empty)* | Comma-separated detector **families** to additionally block. |

The family override is broader but noisier. `disrobe`'s source-level obfuscation classifiers (`js.deob`, `lua.deob`, `py.deob`) are tuned to *attempt* recovery aggressively, so they can fire at high confidence on ordinary text and markdown. Enabling `DISROBE_BLOCK_FAMILIES=obfuscator-wrapper,packer-archive` will catch source-level obfuscation but expect false positives on benign files; scope it with the hook's `files:`/`exclude:` patterns.

```yaml
repos:
  - repo: https://github.com/1-3-7/disrobe
    rev: v0.10.6
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
