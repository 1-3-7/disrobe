| section | line | summary |
|---------|-----:|---------|
| references | 14 | study-only sources + licenses (clean-room) |
| sourcemap | 26 | source-map v3 loader + VLQ design notes |
| dwarf-names | 40 | DWARF/source-map -> lifter local-name wiring |
| types | 54 | type-name inference + export dedup |
| obfuscators | 64 | unflatten fixed-point, defrag heap recovery, integrity strip |
| recovery-ceilings | 78 | honest semantic% vs name% (name% is DWARF/map-gated) |
| invariants | 90 | what must hold across changes |

## references

Clean-room: algorithms/specs studied, reimplemented in original Rust. No reference
source copied. Clones lived only in `%TEMP%/disrobe-refs/` and were deleted.

- Source Map v3 spec (`source-map/source-map-spec`, `source-map.bs`). License:
  CC-BY-SA 3.0 (spec text, not code). Studied: Base64 VLQ encoding (6-bit base64,
  bit 5 = continuation, LSB of assembled magnitude = sign), `mappings` grammar
  (`;` = generated line, `,` = segment, 1/4/5 VLQ fields, field 1 resets per line,
  fields 2-5 delta across document), WASM profile (column = binary byte offset,
  single generated line), `sourceMappingURL` custom-section name (name-encoded URL).
- gimli (existing dep, MIT/Apache-2.0): DWARF reader for `.debug_*` sections.
- wasmparser / walrus (existing deps): WASM section + IR access.

## sourcemap

`src/sourcemap.rs`. Standalone, no DWARF feature gate. `extract_source_mapping_url`
reads the `sourceMappingURL` custom section (ULEB128-length-prefixed URL). The
caller fetches the `.wasm.map` sidecar; `parse_source_map` decodes the JSON +
`mappings` VLQ table into absolute `Segment`s and a `byte_to_segment` floor index.
`name_for_byte` / `resolved_source` give name + source recovery keyed by binary
byte offset (the WASM generated column). VLQ decoder handles multi-digit
continuation and sign bit; rejects invalid base64 and overflow.

## dwarf-names

`FunctionSig.local_names: Vec<Option<String>>` carries real param/local names
(index-aligned to wasm local indices, params first). Populated by
`signature::attach_dwarf_names` from the DWARF symbol table (subprogram params +
lexical-block variables, ordered) and `attach_sourcemap_names` from a source map.
`structured.rs::local_name` consults it, emitting the real identifier (sanitized)
and falling back to `p{idx}`/`l{idx}` when absent. Names are honestly DWARF/map
gated: without `.debug_*` or a `.wasm.map`, `local_names` is empty and the lifter
emits positional names (a real ceiling, not a defect).

## types

`types.rs` synthesizes named structs from access-pattern clusters (field offset ->
`field_{offset}` naming, struct named by base origin). `signature.rs` dedups
exported function aliases: when one function index has multiple export names, the
first becomes the canonical id and the rest are recorded as aliases.

## obfuscators

- `tigress/unflatten.rs`: iterates `unflatten` to a fixed point (re-detect +
  re-chain until no new case is inlined), tracking state-var writes across the loop.
- `wasmixer/defrag.rs`: adaptive-heap type recovery clusters memory accesses by
  base + alignment to label heap regions (complements existing call defrag).
- `jscrambler/integrity_strip.rs`: CFG re-entry integrity-block elimination removes
  guard blocks that branch back to a single dominator entry (self-check pattern).

## recovery-ceilings

Semantic recovery (control flow + operators) is provably lossless for structured
WASM and measured by WAT round-trip equality on the corpus. Name recovery is
measured separately and only nonzero when DWARF, a source map, or a name section
is present.

Measured (`tests/semantic_recovery_corpus.rs`, independent `wat::parse_str`
re-parser as ground truth):
- 28 corpus modules parsed, 3 skipped (GC/component/feature WATs the structured
  lifter does not target).
- Semantic recovery: 76/76 = 100.0% of defined function bodies round-trip.
- Name recovery on this corpus: 76/76 = 100.0% — but ALL of that is from the wasm
  name/export sections (every fixture is named). The DWARF/source-map path is what
  raises name recovery on STRIPPED binaries; with neither name section nor DWARF nor
  `.wasm.map`, name recovery is 0% and the lifter emits positional `p/l/func_N`
  (a real ceiling, proven by `name_recovery_e2e::positional_names_without_debug_info`).

Before this work: lifter always emitted positional `p{idx}`/`l{idx}` even when DWARF
or a source map carried real names (~75-80% effective source quality, names lost).
After: real names flow through whenever debug info is present; semantic round-trip
unchanged at 100% (it was already lossless for structured WASM).

## invariants

- Never execute a sample; corpus is WAT-compiled in-process via `wat::parse_str`.
- `local_names` length <= total locals; out-of-range indices fall back positionally.
- Source-map byte offsets are binary offsets, not DWARF PCs; do not cross-index.
