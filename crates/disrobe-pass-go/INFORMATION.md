| section | line | summary |
|---------|-----:|---------|
| architecture | 12 | module map and analysis data flow |
| signature-scan | 23 | magic-stomp-resilient pclntab recovery design |
| generics | 40 | go 1.18+ generic-instantiation recovery |
| dwarf | 51 | dwarf type-param/local recovery on stripped-with-debug |
| garble-wall | 58 | three garble effects: structure, names, literals |
| refs-licenses | 84 | study-only references and their licenses |
| measured | 92 | honest before/after recovery numbers on the corpus |
| invariants | 112 | what must hold across changes |

## architecture

`analyze()` (lib.rs) is the entry point. Flow: `GoImage::parse` (binary.rs, object crate) →
`locate_pclntab` (pclntab.rs) → `parse_symbols` (symbols.rs) → `locate_moduledata`
(moduledata.rs) → `extract_typemeta` (types.rs) → stripped/garble/embed reports.

pclntab location is layered: (1) magic+structural scan over sections, (2) if that fails,
`signature_scan_pclntab` reconstructs the header VA by scanning for a moduledata whose first
pointer is a self-consistent pclntab and patches a stomped magic. moduledata location is
layered: (1) `runtime.firstmoduledata` symbol, (2) back-search for the pclntab VA pointer.

## signature-scan

`signature_scan_pclntab` (pclntab.rs) handles binaries where the pclntab magic was stomped
(garble randomizes it) but the table body survives. Algorithm (clean-room, modeled on
GoReSym `objfile/pe.go::pcln_scan` + `moduledata_scan`):

1. For each known pclntab VA candidate, validate the body STRUCTURALLY without trusting the
   magic: bytes[4]==0, bytes[5]==0, quantum in {1,2,4}, ptr_size in {4,8}, then parse the
   per-version offset words and require them in-bounds, non-zero, and that the funcname table
   begins with a plausible C-string. A coincidental magic fails these checks.
2. To find candidate VAs when the magic itself is destroyed: scan every pointer-aligned word
   in writable/rodata sections; treat each as a hypothetical moduledata base; read word 0 as
   the pclntab VA; if the bytes at that VA pass structural validation under ANY of the four
   known magics, accept and synthesize the version from the patched magic.

Validation is the security boundary: we never emit a pclntab we could not structurally parse.

## generics

`parse_generic_type_info` (types.rs) recovers Go 1.18+ generic instantiations. Go monomorphizes
generics via GC-shape stenciling: instantiated FUNCTIONS keep names like
`main.Sum[go.shape.int]`, `main.MapKeys[go.shape.string,go.shape.int]` in the pclntab funcname
table; instantiated TYPES appear in typelinks as bracketed names (e.g.
`sync.HashTrieMap[interface {},interface {}]`). We harvest both, split base vs type-arg list,
and normalize `go.shape.X` shapes. Honest limit: GC-shape stenciling collapses distinct type
args to a shared shape, so the recovered arg is the SHAPE (`go.shape.int`), not always the
source type; we surface the shape verbatim and do not fabricate the pre-monomorphization arg.

## dwarf

`dwarf_recover` (types.rs, behind the always-on path when `.debug_info` is present) uses the
`gimli` reader to walk DW_TAG_structure_type / DW_TAG_subprogram and pull type-parameter and
local-variable names that survive on `go build` WITHOUT `-w` (DWARF kept). Go strips DWARF on
`-ldflags=-w`; when present it is the richest source of local names the pclntab never carries.

## garble-wall

Three distinct garble effects, three distinct outcomes:

1. STRUCTURE — the `hello_garble.exe` fixture (`garble -literals -tiny`) KEEPS its pclntab,
   so the signature scan (with magic-stomp recovery) reconstructs all 2091 funcs, 561 types,
   22 itabs, and the generic instantiations. Empirically verified: the fixture contains
   `runtime.main`/`main.main` and the funcname table is intact. The recovered USER names are
   the garble HASHES verbatim (`internal/sync.(*CWQFRMIDV).xYiPuxqUqs`) — we read them
   faithfully, we do not invent the pre-hash name.

2. NAMES — garble name-hashing replaces each package/symbol/field name with
   `base64(hmac-sha256(name, buildseed))[:n]`. The seed is NOT embedded in a `-trimpath`
   build, so the original names are an INFORMATION-THEORETIC wall — no inversion exists. The
   `function_name_looks_garble_hashed` heuristic only DETECTS hashed names (low readable-run,
   dense case-alternation or embedded digit); it never claims to reverse them.

3. LITERALS — `garble -literals` obfuscates string literals with a per-literal FULL-LENGTH
   random key and reverses it in an init thunk. `recover_strings` reverses the statically
   tractable subset: single-byte XOR/ADD/SUB and short repeating-key XOR, each gated by a
   key-histogram OUTLIER test plus a dictionary/phrase check so brute force over a multi-MB
   `.rdata` does not avalanche into false positives (proven by `single_op_scan_quiet_on_random_data`
   and the ground-truth `single_op_scan_recovers_known_xor_blob`). garble's full-length-key
   scheme is NOT reversed here — that needs init-thunk emulation — and `literal_recovery_limit`
   documents this. The fixture's own source literals are confirmed NOT recoverable statically.

## refs-licenses

Study-only (algorithms studied, code reimplemented original in Rust; no source copied):
- GoReSym (github.com/mandiant/GoReSym) — MIT — pclntab magic-stomp scan + moduledata scan.
- Go runtime source (`%GOROOT%/src/runtime/symtab.go`, `internal/abi/type.go`) — BSD-3-Clause
  — moduledata field order, pcHeader layout, abi.Type layout.
Clones lived in `%TEMP%/disrobe-refs/`, deleted after study.

## measured

Corpus = real go1.26.3 PE binaries (tests/fixtures, git-ignored, regen.ps1). Numbers from the
`measure` example, ground-truthed against each binary's OWN pclntab/typelinks (not a re-emit).

| fixture | before funcs | after funcs | before named-types | after named-types | notes |
|---------|-------------:|------------:|-------------------:|------------------:|-------|
| hello_normal | 2085 | 2085 | 557/557 | 557/557 | already 100%; +2731 dwarf-detailed fns |
| hello_stripped | 2085 | 2085 | 557/557 | 557/557 | via pclntab backsearch; no dwarf (-w) |
| hello_magic_stomped | 0 | 2085 | 0 | 557/557 | signature_scan magic-stomp recovery |
| hello_garble (-literals -tiny) | 0 | 2091 | 0 | 561/561 | structure recovered; user NAMES are garble hashes (wall) |
| hello_generics | 1953 | 1962 | 530/530 | 532/532 | +50 generic fns, 5 user generic instantiations, 2549 dwarf-detailed |

Item-by-item honest before/after:
- signature_scan: magic-stomped & garble-tiny binaries 0 -> full pclntab (2085 / 2091 funcs).
- generics: 0 -> 56-65 structured instantiations per generics binary (5 user, rest stdlib).
- dwarf: 0 -> ~2550-2770 functions gain param/local/type-param names (non-stripped only).
- garble literals: full-key scheme NOT statically reversible; single/repeating-key subset is
  reversed and proven on synthetic ground truth; seedless name-hashing is the irreversible wall.

## invariants

- Never emit a pclntab/moduledata that failed structural validation.
- Recovered names/types must come from the binary's own tables, never synthesized.
- `#![forbid(unsafe_code)]`; all reads bounds-checked via `data_at_va`/`read_*`.
- Generic recovery surfaces `go.shape.*` verbatim; never fabricates the source type arg.
- garble seedless name recovery is impossible; quality never claims `Full` without a seed.
