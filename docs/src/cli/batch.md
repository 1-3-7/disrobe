# Batch directory processing

`disrobe auto` accepts a directory as well as a single file. Point it at a directory and it walks the tree, runs the auto-chain on every file, writes each file's outputs under `out/<relative-stem>/`, and emits one aggregate `out/manifest.json`.

Single-file behavior is unchanged: `disrobe auto <file>` still writes `chain.json` + `recovery.json` into a single out dir.

## Usage

```bash
disrobe auto ./samples
disrobe auto ./samples --out ./out/triage --include '**/*.pyc' --exclude '*_test.*' --jobs 4
```

If `--out` is omitted, batch output lands in `./out/<dir-name>-batch/`.

## Flags (batch-only)

| Flag | Effect |
|---|---|
| `--batch-max-depth <N>` | Maximum directory recursion depth (default: unlimited). Depth 0 is the directory itself; depth 1 is its immediate children. |
| `--include <GLOB>` | Only process files matching this glob. Repeatable. With no include, all files are in scope. |
| `--exclude <GLOB>` | Skip files matching this glob. Repeatable. Exclude wins over include. |
| `--jobs <N>` | Bounded worker concurrency. Default is `1`, kept conservative because chains can be memory-heavy. Raise it on machines with headroom. |

The `--max-depth <N>` (default 8), `--capture-stages`, `--emit recovery`, and global flags continue to apply. `--max-depth` is the per-file chain depth; `--batch-max-depth` is the directory recursion depth.

### Glob syntax

Globs match against the slash-normalized path relative to the root.

| Token | Matches |
|---|---|
| `*` | Any run of characters within a single path segment (does not cross `/`). |
| `**` | Any run including `/` (spans directories). |
| `?` | Exactly one non-`/` character. |
| `[abc]`, `[a-z]`, `[!0-9]` | A character class, with `!`/`^` negation and `a-z` ranges. |

A bare pattern with no `/` (for example `*.bin`) also matches files in subdirectories, so the common "all `.bin` files" case works without writing `**/`.

## `manifest.json`

Schema `disrobe.batch.manifest/v1`:

```json
{
  "schema": "disrobe.batch.manifest/v1",
  "tool_version": "0.10.4",
  "root": "samples",
  "out_root": "out/samples-batch",
  "chain": "auto:8",
  "jobs": 4,
  "summary": { "processed": 12, "recovered": 9, "detect_only": 2, "errors": 1 },
  "entries": [
    {
      "input": "samples/app.pyc",
      "relative": "app.pyc",
      "size": 4096,
      "detected_format": "Python",
      "chain": ["py.decompile"],
      "verdict": "Complete",
      "recovery_score": 0.67,
      "output_dir": "out/samples-batch/app.pyc",
      "duration_ms": 31,
      "error": null
    }
  ]
}
```

- **recovery_score** is the mean per-pass confidence-tier rank across the chain, normalized to `[0, 1]` (skeleton 0, partial 0.33, semantic 0.67, exact 1.0), or `null` when no pass ran.
- A file that fails (unreadable, or its chain errors) is recorded with a non-null `error` and counted under `summary.errors`; one bad file never aborts the batch.
- Files with no pass in their chain are counted as `detect_only`.

The human-readable summary line mirrors the manifest: `N processed, M recovered, K detect-only, E errors`.
