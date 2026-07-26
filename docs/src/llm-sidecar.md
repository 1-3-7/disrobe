# Metadata sidecar and provenance

`disrobe` can emit a structured metadata bundle beside recovered output. The bundle carries call graph, types, control flow, capability surface, decompile provenance, and round-trip verdicts in one schema-conforming sidecar. It is deterministic data derived from the same pass results as the human output; no model runs in the recovery path.

## Turning it on

```sh
disrobe py decompile module.pyc --out recovered/ --metadata-pack-4
disrobe py decompile module.pyc --out recovered/ --metadata-pack-4 --llm-briefs
```

`--llm` remains as a compatibility alias for the full **Pack-4** selection. Prefer `--metadata-pack-4` in new scripts. `--llm-briefs` additionally renders `AGENTS.md` and `SKILL.md` reconstruction briefs next to the bundle.

By default the bundle is written next to the primary output as `<stem>.disrobe.llm.json`. Override with `--metadata-out <path>` and choose the format with `--metadata-format json|jsonl|cbor|msgpack`.

## The four packs

Packs are cumulative presets over the 18 categories:

| Pack | Flag | Adds |
|---|---|---|
| Pack-1 | `--metadata-pack-1` | ast + disasm + symbols + strings |
| Pack-2 | `--metadata-pack-2` | Pack-1 + cfg + types + imports + provenance |
| Pack-3 | `--metadata-pack-3` | Pack-2 + dfg + signatures + constants + roundtrip + sourcemap + manifest |
| Pack-4 | `--metadata-pack-4` / `--llm` | Pack-3 + confidence + opcode-coverage + pii-map + decryption-keys (auth-gated) |

## The 18 categories

Each category can also be toggled individually:

```text
ast  disasm  cfg  dfg  symbols  strings  types  imports  constants  signatures
provenance  roundtrip-verdict  source-map  manifest-cat  decryption-keys
confidence  opcode-coverage  pii-map
```

Fine-tune any pack:

```sh
disrobe py decompile m.pyc --metadata-pack-3 --metadata-exclude ast,symbols
disrobe py decompile m.pyc --metadata-include cfg,types,provenance
```

## Auth-gated categories

The `decryption-keys` category exposes recovered keys and IVs and is gated: passing `--decryption-keys` without `--i-have-authorization` fails with `DR-CLI-0420`. Other legally sensitive recovery paths document their own authorization gate where the CLI exposes one.

## Provenance sidecars

Independently of the metadata bundle, a chain run writes two provenance artifacts:

- `recovery.json`: per-pass status, confidence-tier histogram, and timings. Summarize with `disrobe context --out <dir>`.
- `provenance/<file>.map.json`: a line-level map from each recovered source line to `(pass, source_offset, opcode_range, confidence)`. A reviewer traces any line of recovered source back to the exact bytes it came from, and to the confidence of that recovery.

## The `.disrobe/` workspace

Scaffold a full agent workspace in the current directory:

```sh
disrobe init                    # scaffold .disrobe/
disrobe init --ide claude       # also generate IDE-specific settings (claude, cursor, windsurf, aider)
```

This lays down an `AGENTS.md` forensic-framing template, per-symbol annotation schemas under `.disrobe/annotations/`, skill packs under `.disrobe/skills/`, slash commands, and a settings hook template that denies edits to ground-truth stage directories (see [Diff and guard tooling](./cli/diff-guard.md)). Maintain it with:

```sh
disrobe annot refresh           # rebuild .disrobe/annotations/<stem>.annot.json
disrobe rename oldName newName --note "why"   # append-only rename record
disrobe context --out recovered/              # summarize the recovery report
```
