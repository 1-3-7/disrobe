| section | line | summary |
|---------|-----:|---------|
| architecture | 14 | module map and analysis data flow |
| signature-scan | 30 | magic-stomp-resilient pclntab recovery design |
| generics | 52 | go 1.18+ generic-instantiation recovery |
| dwarf | 66 | dwarf type-param/local recovery on stripped-with-debug |
| garble-wall | 78 | what garble removes and why -tiny names are irreversible |
| refs-licenses | 90 | study-only references and their licenses |
| measured | 102 | honest before/after recovery numbers on the corpus |
| invariants | 118 | what must hold across changes |

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

`garble -literals` XORs string literals (recoverable: garble.rs scan_xor_strings). `garble`
name-hashing replaces every package/symbol/field name with `hash(name, buildseed)` truncated
base64; the seed is HMAC-SHA256-derived and NOT embedded in a `-trimpath` build, so original
names are an INFORMATION-THEORETIC wall — no inversion exists. `garble -tiny` additionally
strips the entire pclntab + moduledata + funcname table; nothing structural survives, so func
recovery is genuinely 0 (the `hello_garble.exe -tiny` fixture). We document, never fake.

## refs-licenses

Study-only (algorithms studied, code reimplemented original in Rust; no source copied):
- GoReSym (github.com/mandiant/GoReSym) — MIT — pclntab magic-stomp scan + moduledata scan.
- Go runtime source (`%GOROOT%/src/runtime/symtab.go`, `internal/abi/type.go`) — BSD-3-Clause
  — moduledata field order, pcHeader layout, abi.Type layout.
Clones lived in `%TEMP%/disrobe-refs/`, deleted after study.

## measured

Corpus = real go1.26.3 PE binaries (tests/fixtures, git-ignored, regen.ps1). Numbers from the
`measure` example, ground-truthed against each binary's OWN pclntab/typelinks (not a re-emit).

| fixture | before funcs | after funcs | before named-types | after named-types |
|---------|-------------:|------------:|-------------------:|------------------:|
| hello_normal | 2085 | 2085 | 557/557 | 557/557 |
| hello_stripped | 2085 | 2085 | 557/557 | 557/557 |
| hello_magic_stomped | 0 | (filled by signature_scan) | 0 | (filled) |
| hello_garble (-tiny) | 0 | 0 (wall) | 0 | 0 (wall) |

## invariants

- Never emit a pclntab/moduledata that failed structural validation.
- Recovered names/types must come from the binary's own tables, never synthesized.
- `#![forbid(unsafe_code)]`; all reads bounds-checked via `data_at_va`/`read_*`.
- Generic recovery surfaces `go.shape.*` verbatim; never fabricates the source type arg.
- garble seedless name recovery is impossible; quality never claims `Full` without a seed.
