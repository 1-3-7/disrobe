# 5. Ship a first-class metadata sidecar mode with provenance

- Status: accepted
- Date: 2025-09-29
- Deciders: project maintainer

## Context and Problem Statement

Downstream tooling needs more than rendered source. A consumer handed only recovered text must re-derive structure the decompiler already computed: call graph, control flow, types, the capability surface, and how much to trust each recovered symbol. Re-deriving that is wasteful and lossy: the consumer cannot recover the round-trip verdict or the line-level provenance because that information never reached it. We must decide whether to treat machine consumption as a first-class output with a stable schema, or leave it to downstream tooling to scrape from human-oriented text. The decision is also a safety one: a metadata bundle that leaks recovered decryption keys or PII by default would be a footgun.

## Decision Drivers

- Consumers should inspect recovered code without re-deriving structure disrobe already has.
- Every recovered symbol must carry a trust signal (confidence tier, round-trip verdict) so a consumer knows how far to trust it.
- The decompile path must stay **deterministic** - no model may run inside it, or output stops being reproducible.
- Sensitive categories (recovered keys, PII) must be off by default and gated.
- The output must drop straight into downstream tooling without bespoke glue.

## Considered Options

1. **A first-class, schema-conforming metadata sidecar (`--metadata-pack-*`, with `--llm` retained as a compatibility alias)** with cumulative packs over 18 categories, line-level provenance maps, round-trip verdicts, and auth-gated sensitive categories. No model in the decompile path; the sidecar is derived from artifacts disrobe already computed.
2. **No special mode; let consumers scrape rendered source.** Zero new surface, but every consumer re-derives structure, loses the round-trip verdict and provenance entirely, and there is no trust signal.
3. **An in-loop model that decompiles with generated guesses.** Potentially higher surface fluency on hard inputs, but it destroys determinism, makes output non-reproducible, and makes the tool unusable as a forensic baseline.

## Decision Outcome

Chosen option: **the first-class metadata sidecar**. Any pass can emit a schema-conforming metadata bundle covering 18 categories, organized into four cumulative packs (Pack-1 ast+disasm+symbols+strings, up to Pack-4/`--metadata-pack-4` adding confidence, opcode-coverage, pii-map, and auth-gated decryption-keys). `--llm` remains as a compatibility alias for Pack-4. Alongside it, a chain run writes `recovery.json` (per-pass status, confidence histogram, timings) and `provenance/<file>.map.json` (a line-level map from each recovered source line back to `(pass, source_offset, opcode_range, confidence)`). `--llm-briefs` additionally renders `AGENTS.md` / `SKILL.md` reconstruction briefs. **No model runs in the decompile path**; RNG-backed backends take an explicit `--seed`.

## Consequences

- **Good:** a reviewer can trace any line of recovered source back to the exact bytes it came from and how confident the recovery is, and knows per-symbol how much to trust the output via the propagated confidence tiers.
- **Good:** determinism is preserved end to end - because no model sits in the decompile path and the sidecar is purely derived, the `.dr` envelope stays content-addressable and `disrobe diff` stays meaningful.
- **Good:** `disrobe init` scaffolds a `.disrobe/` analysis workspace (forensic-framing `AGENTS.md`, per-symbol annotation schemas, skill packs, slash commands, a guard hook denying edits to ground-truth stage directories), so the output is ready for review tooling.
- **Good / safety:** sensitive categories are off by default; `decryption-keys` is gated by `--i-have-authorization` and fails with `DR-CLI-0420` otherwise, and a `pii-map` is opt-in.
- **Bad / accepted cost:** 18 categories, four packs, two provenance sidecars, and brief generation are a substantial surface to keep schema-stable and tested across every pass that emits them.
- **Bad / accepted cost:** the deliberate refusal to put a model in the decompile path forgoes potential recovery gains on the hardest inputs; we accept lower ceiling recovery in exchange for reproducibility, which is non-negotiable for the forensic use case.
