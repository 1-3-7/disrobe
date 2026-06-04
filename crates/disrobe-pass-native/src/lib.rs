#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::single_match_else,
    clippy::format_push_string,
    clippy::manual_strip,
    clippy::missing_const_for_fn,
    clippy::unnecessary_wraps,
    clippy::unnecessary_map_or,
    clippy::single_char_pattern,
    clippy::match_same_arms,
    clippy::manual_is_multiple_of,
    clippy::iter_on_single_items,
    clippy::redundant_else
)]

pub mod arch;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod crypto_consts;
pub mod cxx_recovery;
pub mod debug_info;
pub mod decompile;
pub mod error;
pub mod fingerprint;
pub mod fixtures;
pub mod flirt;
pub mod format;
pub mod format_wire;
pub mod lang;
#[cfg(feature = "llm-metadata")]
pub mod llm;
pub mod obfuscators;
pub mod packers;
pub mod pass;
pub mod provenance_header;
pub mod rust_recovery;
pub mod stub_emu;

pub mod entropy;

pub use arch::{Arch, DisasmInsn, disassemble};
pub use crypto_consts::{
    CryptoConstConfidence, CryptoConstHit, CryptoPrimitive, detect_crypto_constants,
};
pub use cxx_recovery::{
    CxxAbi, CxxDemangled, EhEntry, RttiEntry, SehScopeEntry, demangle_auto, demangle_itanium,
    demangle_msvc, parse_itanium_lsda, parse_windows_seh_scope_table, recover_itanium_rtti,
};
pub use debug_info::{
    DwarfSummary, DwarfVersion, PdbSummary, StabsEntry, classify_dwarf_versions, parse_stabs,
    summarize_dwarf, summarize_pdb,
};
pub use decompile::{
    DecompileOutput, DecompilerBackend, Probe, lift_llvm_ir_to_pseudo_c, probe, probe_all, run,
};
pub use error::{Error, Result};
pub use fingerprint::{
    ASCII_XREF_MIN_LEN, FINGERPRINT_SCHEMA, FingerprintSidecar, StringXref, extract_ascii_xrefs,
};
pub use fixtures::{
    minimal_elf64, minimal_macho64, minimal_pe32, packed_upx_elf64_marker, tiny_coff_x64,
};
pub use flirt::{
    FlirtArch, FlirtHeader, FlirtMatch, FlirtModule, FlirtPattern, FlirtPublicName, FlirtSig,
    crc16_flirt, match_flirt, parse_flirt,
};
pub use format::{DetectedFormat, NativeFormat, detect as detect_format};
pub use format_wire::{
    format_c as format_c_lifted, format_cpp as format_cpp_lifted,
    format_objc as format_objc_lifted, format_rust as format_rust_lifted,
    format_swift as format_swift_lifted,
};
pub use lang::{LanguageHit, NativeLanguage, detect as detect_languages};
#[cfg(feature = "llm-metadata")]
pub use llm::{
    METADATA_CAPABILITY as NATIVE_METADATA_CAPABILITY, NativeImport, NativeInstr, NativeLlmInput,
    NativeSymbol,
};
pub use obfuscators::{
    CffUnflattenReport, ObfuscatorFamily, ObfuscatorHit, StringDecryptHit,
    decrypt_strings_for_family, detect as detect_obfuscators, strip_ollvm_bcf_stub,
    undo_emotet_cff_stub, undo_ollvm_substitution_stub, unflatten_ollvm_stub,
    unflatten_tigress_stub,
};
pub use packers::{
    AspackPhaseTwoOutput, CHAIN_SIGNATURES, CarvedVmpSection, ChainDetection, ChainSignature,
    Confidence, Detection as PackerDetection, DisFilterStreamSizes, FsgImport, FsgUnpackOutput,
    KkrunchyByteRecoveryReport, KkrunchyClassicStream, KkrunchyEmulatedUnpackOutput,
    KkrunchyEmulationSnapshot, KkrunchyEmulator, KkrunchyHeaderInfo, KkrunchyPhaseTwoOutput,
    KkrunchyUnpackOutput, KkrunchyVariant, MewEmulatedOutput, MewImport, MewLeadingChunk,
    MewLzmaProps, MewRecovery, MewUnpackOutput, MpressImport, MpressInfo, MpressRecoveryStatus,
    MpressUnpackOutput, NspackEmulatedReport, NspackLayout, NspackRecoveryStatus, NspackSection,
    NspackUnpackReport, OreansProduct, Packer, PetitePhase2EmulatedOutput, PetiteUnpackReport,
    PetiteUnpackResult, RecoveredImport, RecoveredImportFn,
    RecoveredResource as NspackRecoveredResource,
    RecoveredSectionName as NspackRecoveredSectionName, SectionPerms, SyntheticImport, ThemidaCarve,
    UnpackerStatus, UpxMethod, UpxPackHeader, UpxUnpackOutput, VmProtectCarve, carve_themida,
    carve_vmprotect, compute_byte_recovery, decompress_kkrunchy_classic, detect as detect_packers,
    detect_packer_chain, dis_filter, dis_unfilter, fingerprint_chain, locate_classic_stream,
    parse_kkrunchy_header, parse_nspack_layout, unpack_aspack_phase2_emulated, unpack_fsg,
    unpack_kkrunchy, unpack_kkrunchy_emulated, unpack_kkrunchy_phase2_emulated, unpack_mew,
    unpack_mew_emulated, unpack_mpress, unpack_nspack, unpack_nspack_emulated,
    unpack_nspack_emulated_with_baseline, unpack_nspack_emulated_with_baseline_raw, unpack_petite,
    unpack_petite_phase2_emulated, unpack_petite_with_report, unpack_upx,
};
pub use pass::{
    DecompilerProbeSummary, NativePass, NativePassReport, PASS_INPUT_PATH_CAP, PassInput,
    decode_pass_input, distinct_packer_labels,
};
pub use provenance_header::{
    c_lifted_header, cpp_lifted_header, render_c_with_header, render_cpp_with_header,
    render_rust_with_header, rust_lifted_header,
};
pub use rust_recovery::{
    AuditableCrate, AuditableSbom, DemangleScheme, DemangledSymbol, EnumDiscriminant,
    MonomorphizationGroup, PanicKind, PanicSignature, VtableEntry, demangle as demangle_rust,
    detect_panic_signatures, group_monomorphizations, parse_auditable_section,
    recover_enum_discriminants, recover_trait_vtables,
};

pub use entropy::{
    ENTROPY_WINDOW_4K, EntropyBlock, HIGH_ENTROPY_THRESHOLD, locate_high_entropy,
    shannon_entropy_bits, windowed_entropy,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[must_use]
pub const fn version() -> &'static str {
    VERSION
}
