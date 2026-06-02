# CLI overview

Every disrobe operation follows one shape:

```sh
disrobe <pass> <action> <input> [--out <path>] [flags]
```

A few top-level commands (`auto`, `chain`, `scan`, `yara`, `status`, `verify`, `passes`, `doctor`) take their arguments directly rather than through a pass/action pair.

## Discovering the surface

```sh
disrobe --help                # every subcommand
disrobe <pass> --help         # actions and flags for one pass, e.g. `disrobe py --help`
disrobe passes                # one-line capability summary per registered pass
disrobe explain DR-CLI-0030   # look up any error code
```

Subcommand inference is enabled: unambiguous prefixes work (`disrobe dec ...` resolves if only one subcommand starts with `dec`).

## Output formats

The output format is a global flag, so it applies to any command:

| Flag | Output |
|---|---|
| (default) | Human-readable text |
| `--json` | A single structured JSON document |
| `--ndjson` | Newline-delimited JSON (streaming) |
| `--sarif` | SARIF 2.1.0, for GitHub code scanning and other SARIF consumers |

```sh
disrobe scan firmware.bin --sarif > findings.sarif
disrobe py decompile m.pyc --json
```

## The standard recovery loop

```sh
disrobe auto input.bin --out recovered/ --capture-stages   # recover
disrobe status                                              # what landed in ./out/
disrobe context --out recovered/                           # per-pass verdict + confidence
disrobe verify recovered/final/*.dr                        # check envelope integrity
```

The next pages cover [global flags](./global-flags.md) in full, the [complete command reference](./reference.md), the [diff and guard tooling](./diff-guard.md), and the [daemon surface](./serve.md).
