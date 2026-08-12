# CLI overview

Ecosystem command families usually nest an action:

```sh
disrobe <pass> <action> <input> [--out <path>] [flags]
```

Other operations take their arguments directly. Examples include `auto`, `scan`, `query`, `taint`, `extract`, `webview`, and `report`. Use `disrobe --help` for the complete surface compiled into your binary; the list changes when optional build features change.

## Discovering the surface

```sh
disrobe --help                # every subcommand
disrobe <pass> --help         # actions and flags for one pass, e.g. `disrobe py --help`
disrobe passes                # direct recovery families plus auto-chain pass IDs
disrobe catalog [ecosystem]   # supported families and recovery tiers
disrobe explain DR-CLI-0030   # look up any error code
```

Subcommand inference is enabled: unambiguous prefixes work (`disrobe dec ...` resolves if only one subcommand starts with `dec`).

## Output formats

The CLI accepts these global output flags. A command can reject a format that does not fit its output contract:

| Flag | Output |
|---|---|
| (default) | Human-readable text |
| `--json` | A single structured JSON document |
| `--ndjson` | Newline-delimited JSON (streaming) |
| `--sarif` | SARIF 2.1.0, for GitHub code scanning and other SARIF consumers |

```sh
disrobe scan firmware.bin --sarif > findings.sarif
```

## The standard recovery loop

```sh
disrobe auto input.bin --out recovered/ --capture-stages   # recover
disrobe status                                              # what landed in ./out/
disrobe context --out recovered/                           # per-pass verdict + confidence
disrobe verify recovered/final/*.dr                        # check envelope integrity
```

The next pages cover [global flags](./global-flags.md) in full, the [complete command reference](./reference.md), the [diff and guard tooling](./diff-guard.md), and the [daemon surface](./serve.md).
