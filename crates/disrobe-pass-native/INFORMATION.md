| section | line | summary |
|---------|-----:|---------|
| refs + licenses | 14 | clean-room reference algorithms studied + their licenses |
| section recovery oracle | 28 | how the section-granule report works + non-circularity |
| lossless packer ceilings | 44 | measured per-section recovery + the named limit |
| mew recovery profile | 64 | file-image alignment + why the residual is rebuilt state |
| chain confidence | 80 | per-stage product scoring rationale |
| rust recovery | 90 | v0-demangled trait/mono parsing + const-spec status |
| invariants | 102 | what must hold across changes |

## refs + licenses

Clean-room only: algorithms/specs studied, reimplemented in original Rust, no
verbatim copy. No new downloads were required for this workstream - the existing
`rustc_demangle` 0.1.27 crate and the in-repo `stub_emu` x86 interpreter covered
everything. Reference algorithms relied on (all reimplemented, none copied):

- aPLib byte-tagged depacker (Joergen Ibsen, BSD) - the MEW fallback decoder, already
  shipped in `mew_unpack.rs` from a prior wave; unchanged this workstream.
- LZMA1 SDK arithmetic coder (7-zip public domain) - `mpress_lzma.rs`, reused by MEW.
- PE/COFF layout (Microsoft PE spec) - `pe_sections.rs` parser, reused by the report.
- rustc-v0 + legacy Rust mangling (rust-lang/rustc-demangle, MIT/Apache-2.0) - the
  demangling backend; const-specialization is fully handled upstream (verified).

## section recovery oracle

`section_recovery.rs` provides `section_recovery_report` (VA-indexed) and
`file_image_section_report` (file-offset-indexed). Both decompose a recovered
image against the INDEPENDENT pre-packed original's loaded/file layout, per
section, classifying each as Content / LoaderRebuilt / Stub. Non-circular: the
baseline (`build_loaded_image`) is derived only from `original.exe`, never from
the packed sample or the recovered output - same convention the ASPack/PECompact
phase-2 content oracle already used, lifted into one shared, audited comparator.
`mismatching_content_sections()` answers "which section costs the last few
percent". `mismatch_runs` distinguishes single-point decoder drift (one run)
from scattered IAT/reloc-slot patching (many runs).

## lossless packer ceilings

Measured with the new report on the real corpus fixtures (AccessEnum, Clockres):

- ASPack:    `.text`/`.data` = 100.00% byte-identical. content 97.05/99.16%.
- PECompact: `.text` = 100.00%. content 94.54/98.93%.

The residual is NOT a decoder defect. It is concentrated entirely in:
  1. `.rsrc` - resource DATA-ENTRY `OffsetToData` RVAs point to where the stub
     relocated the resource bytes (different RVA than the unbound original); the
     resource bytes are present, just at a rebuilt location.
  2. `.rdata` IAT slice - the loader-bound IAT holds resolved/synthetic pointers
     (`0xFE0X_XXXX` emulator addresses), the unbound original holds name-RVAs.

NAMED LIMIT: the recovered MEMORY image is byte-identical in content/code; the
residual is bound-vs-unbound LOADER STATE. Driving it to byte-identical would
require a full PE "unbind" pass (un-relocate + re-unbind IAT + restore `.rsrc`
RVAs). The recovered import directory in these fixtures is bound/rewritten and
not cleanly walkable, so re-unbinding is not deterministically tractable from the
recovered image alone - attempting it would fabricate bytes (honesty mandate) and
risk the green tests. Recorded transparently, not faked.

## mew recovery profile

MEW's LZMA rebuilder emits the original's FILE image (byte i -> original file
offset `file_align + i`; `file_align` = first section's `raw_pointer`, 0x400 or
0x1000). `.text` is 100.00% byte-identical on ALL three fixtures (proven by
`test_mew_*_text_byte_identical`). The whole-file figures (91.80/64.46/95.05%)
are honest: the residual is the IAT at `.rdata[0]` (stored as zeros in the
stream, stub-patched at runtime) plus relocated pointer tables at `.data[0]` plus
`.rsrc`/`.reloc` - all runtime-rebuilt zones physically absent from the LZMA
stream. Autologon is lowest because it is reloc-heavy. The LZMA path is already
PRIMARY (real-by-default); byte-tagged aPLib is the documented fallback.

## chain confidence

`ChainDetection::confidence_score()` -> `ChainConfidenceScore`: each layer's
probability comes from its witnessing byte marker's confidence (High 0.96 /
Medium 0.80 / Low 0.60, matching the single-detection verdicts in
`chain_detector::verdict_for`). Overall = product of stage probabilities = the
joint probability all layers are correctly identified (independent witnesses,
each a distinct non-overlapping byte marker). Guarantees a longer chain scores
strictly below its high-confidence prefix.

## rust recovery

- Const-specialization: handled fully by `rustc_demangle` 0.1.27 (verified
  `<4usize>`, `<42usize>`, `<'char'>`, `<...u64>`, nested `<u8, 8usize>`). No
  extension needed in the demangling backend.
- Structured recovery (operates on demangled strings) was legacy-only; extended:
  - `extract_trait_name`: parses both `$LT$..$u20$as$u20$..$GT$` (legacy) and
    `<Type as Trait>` (v0-demangled) with nested-angle matching. Fixed a
    pre-existing bug where nested `<Vec<T> as Debug>` returned None.
  - `monomorphization_origin`: picks the earliest type-arg bracket across both
    `$LT$` and `<` encodings, so modern-binary monomorphizations group correctly.

## invariants

- All existing native tests stay green (kkrunchy K7_MEASURED_FLOOR_BP=644 guard,
  nspack content floors, mew/aspack/pecompact recovery floors, fsg byte-exact).
- The section oracle is NON-CIRCULAR: baseline derived only from original.exe.
- Never assert an unmeasured number. Floors are the measured value, never above.
- `.text` byte-identity for ASPack/PECompact/MEW is a hard guarantee, tested.
- No packed/sample binary is ever executed (static analysis only).
