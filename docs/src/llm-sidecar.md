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
| Pack-4 | `--metadata-pack-4` / `--llm` | Pack-3 + confidence + opcode-coverage + pii-map + decryption-keys. Only `decryption-keys` is auth-gated. |

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

## Which commands write a bundle

The metadata flags are declared on the root parser, so every subcommand accepts them, but only these commands act on them. Every other subcommand ignores the flags and writes no bundle, and `disrobe auto` rejects them with `DR-CLI-0843` because the chain engine writes a single `chain.json` instead.

| Command | Contributes |
|---|---|
| `disrobe py decompile` | ast, disasm, symbols, strings, imports, constants, signatures, provenance, roundtrip-verdict, source-map, manifest, and cfg + dfg when the input reaches Mir |
| `disrobe py deob` | symbols, strings, provenance, confidence, source-map, and cfg + dfg when the input reaches Mir |
| `disrobe py disasm` | disasm, symbols, strings, constants, opcode-coverage, provenance, and cfg + dfg when the input reaches Mir |
| `disrobe taint` | cfg + dfg |

Every command in this table also contributes pii-map when requested. A dedicated pass (`disrobe-llm-metadata-pii`) scans the raw input bytes for PII-bearing indicators and secret findings, independent of which language command ran, so pii-map behaves like cfg/dfg rather than like the per-language categories above: one shared scan wired into the bundle writer, not a per-command implementation. It reports `applicable: false` with a reason when it finds nothing, distinct from an unimplemented category.

## Control flow and data flow

The `cfg` and `dfg` categories are summaries of the normalized IR, so a command produces them only for an input that reaches the Mir rung. These input families reach it:

- Native PE, ELF and Mach-O binaries, through the disassembler.
- WebAssembly modules, JVM class files, Dalvik `.dex`, managed .NET PE, SWF and raw ABC, Ruby `YARB` bytecode, Lua chunks, BEAM modules, and CPython `.pyc`, each through its own lifter.
- Any Disasm-rung or Mir-rung `.dr` envelope.

Both categories are emitted as one entry describing the whole module. `function` names the unit, `blocks` carries every basic block with the `label` of the function it belongs to, and `edges` carries `from` and `to` block indices with a `kind` of `fallthrough`, `branch_true`, `branch_false` or `jump`. A `functions` array carries the per-function address, export flag, cyclomatic complexity and block count. The `dfg` value reports memory `defs`, the `uses` each def reaches, and `unreached_reads` for reads no write reaches.

An input that never reaches Mir still gets an entry, reported as `applicable: false` with a `reason` naming the rung it did not reach. That is a different fact from a module that does reach Mir and genuinely has nothing to report, which is `applicable: true` with an empty array. A consumer must not treat the two as the same.

## Auth-gated categories

The `decryption-keys` category exposes recovered keys and IVs and is gated: passing `--decryption-keys` without `--i-have-authorization` fails with `DR-CLI-0420`. Other legally sensitive recovery paths document their own authorization gate where the CLI exposes one. The `pii-map` category itself carries no such gate: it emits only a placeholder and a location for each finding, never the matched value, so it adds no secret material of its own. Other categories such as `strings` and `ast` still report full recovered text by design, so a pack-4 bundle as a whole is not a scrubbed artifact.

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
