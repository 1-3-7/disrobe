#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
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

pub mod api_hash;
pub mod arch;
pub mod authenticode;
pub mod backend_export;
#[allow(clippy::redundant_pub_crate)]
mod basic_blocks;
pub mod bindiff;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod crypto_consts;
pub mod cxx_recovery;
pub mod debug;
pub mod debug_info;
pub mod decompile;
pub mod delphi;
pub mod deobf;
pub mod desync;
pub mod disasm_ir;
pub mod dwarf_sourcemap;
pub mod ebpf;
pub mod elf;
pub mod emu_strings;
pub mod encode;
pub mod error;
pub mod fileid;
pub mod fingerprint;
pub mod fixtures;
pub mod flirt;
pub mod format;
pub mod format_wire;
pub mod identify;
pub mod lang;
#[cfg(feature = "llm-metadata")]
pub mod llm;
pub mod obfuscators;
pub mod packers;
pub mod pass;
pub mod patch;
pub mod pdb_cxx;
pub mod plt_resolve;
pub mod provenance_header;
pub mod pseudo_c;
pub mod rust_recovery;
pub mod sig_engine;
pub mod sigmaker;
#[allow(clippy::redundant_pub_crate)]
mod simd_devirt;
pub mod similarity;
pub mod stack_frame;
pub mod stack_string;
pub mod stream_disasm;
pub(crate) use disrobe_cfg as structuring;
pub mod stub_emu;
#[cfg(test)]
#[allow(clippy::redundant_pub_crate)]
mod test_support;
pub mod vm_devirt;

pub mod entropy;
pub mod entropy_viz;

pub use api_hash::{
    ApiHashHit, HashFamily, harvested_hash_constants, resolve_hash, resolve_hash_any_family,
    resolve_imports_by_hash,
};
pub use arch::{Arch, DisasmInsn, Syntax, disassemble, disassemble_x86};
pub use authenticode::{
    AuthenticodeReport, AuthenticodeVerdict, CertInfo, TimestampInfo, verify as verify_authenticode,
};
pub use backend_export::{
    ExportFormat, RebuildLayout, RebuiltImage, RecoveredSymbol, SYMBOL_MAP_SCHEMA, SymbolClass,
    SymbolMap, SymbolOrigin, collect_recovered_symbols, collect_recovered_symbols_with_oep,
    rebuild_passthrough, rebuild_unpacked_pe, render_ghidra_postscript, render_idapython,
    render_symbol_map_json,
};
pub use bindiff::{
    BINDIFF_SCHEMA, BinDiffReport, CfgFingerprint, ChangeKind, ChangedFunction, FunctionPrint,
    diff as bindiff,
};
pub use crypto_consts::{
    CryptoConstConfidence, CryptoConstHit, CryptoPrimitive, detect_crypto_constants,
};
pub use cxx_recovery::{
    CxxAbi, CxxBaseLink, CxxClass, CxxDemangled, CxxHierarchy, CxxInheritance, CxxVtable,
    CxxVtableSlot, EhEntry, RttiEntry, SehScopeEntry, StlTemplate, demangle_auto, demangle_itanium,
    demangle_msvc, detect_stl_templates, parse_itanium_lsda, parse_windows_seh_scope_table,
    recover_cxx_hierarchy, recover_itanium_rtti,
};
pub use debug_info::{
    DwarfSummary, DwarfVersion, PdbBinaryMatch, PdbRecovery, PdbSummary, PdbSymbolInfo,
    PdbSymbolKind, PdbTypeInfo, PdbTypeKind, StabsEntry, classify_dwarf_versions, parse_stabs,
    recover_pdb, summarize_dwarf, summarize_pdb,
};
pub use decompile::{
    DecompileOutput, DecompilerBackend, Probe, lift_llvm_ir_to_pseudo_c, probe, probe_all, run,
};
pub use delphi::{
    DelphiClass, DelphiEra, DelphiForm, DelphiMethod, DelphiProperty, DelphiReport,
    analyze as analyze_delphi, detect_delphi, recover_delphi_classes, recover_dfm_resources,
};
pub use deobf::{
    AbiInference, ArgCount, Bits as DeobfBits, BlockCopyProp, BlockDeadFlags, BogusBranch,
    BranchFoldFinding, BranchFoldOutcome, CallingConvention, CffOutcome, CffRecovery,
    CopyPropOutcome, CopyPropReport, DeadEdge, DeadFlagOutcome, DeadFlagReport, DeobfReport,
    FoldKind, FoldVerdict, OpaquePredicateSimplification, OpaqueResult, PathSenseReport,
    PathSenseWall, ReturnKind, StateLoc as CffStateLoc, SubstitutionResult,
    analyze_path_constraints, clean_dead_flags, clean_register_copies,
    clean_register_copies_live_out, copy_propagate_block, copy_propagate_block_live_out,
    defeat_bogus_control_flow, defeat_cff, eliminate_dead_flags, eliminate_dead_flags_live_out,
    fold_constant_branch, infer_function_abi, prove_dead_paths, undo_substitution,
};
pub use desync::{
    Bitness, ByteRange, CodeWindow, DesyncReport, DiscoveredFunctions, DiscoveryInput,
    JumpTableHit, ReadOnlyWindow, RecoveredInsn, UnresolvedKind, UnresolvedTarget,
    VmwareBackdoorHit, cleaned_listing as desync_cleaned_listing, discover_functions,
    is_noreturn_import_name, noreturn_import_seeds, resolve as resolve_desync,
    resolve_with_noreturn as resolve_desync_with_noreturn, scan_vmware_backdoor,
    vmware_backdoor_port,
};
pub use disasm_ir::{
    FunctionSpan, build_disasm_payload, function_spans, is_disassemblable_format,
    seh_scope_function_starts, text_section_window,
};
pub use dwarf_sourcemap::{
    CompileUnit, CoverageScore, DwarfSourcemap, LineRow, ReconstructedType, SplitDwarfInfo,
    TypeKind, TypeMember, TypeReconstruction, reconstruct_dwarf_types, synthesize_dwarf_sourcemap,
};
pub use ebpf::{EBPF_INSN_SIZE, EbpfRecovery, ebpf_helper_name, recover_ebpf_program};
pub use elf::{
    DynamicSymbol, ElfClass, ElfData, ElfDynamicReport, RelocSource, Relocation, SegmentMapping,
    SymbolBind, SymbolCountSource, SymbolType, analyze as analyze_elf_dynamic,
};
pub use emu_strings::{DecoderCandidate, EmulatedString, emulate_string_decoders};
pub use encode::{RelocatedBlock, decode_all, encode_instruction, relocate_block};
pub use error::{Error, Result};
pub use fileid::{Evidence, EvidenceKind, FileIdReport, Finding, identify as identify_file};
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
pub use identify::{
    IdentityHit, IdentityKind, IdentityReport, SupportRoute, detect as detect_identity,
};
pub use lang::{LanguageHit, NativeLanguage, detect as detect_languages};
#[cfg(feature = "llm-metadata")]
pub use llm::{
    METADATA_CAPABILITY as NATIVE_METADATA_CAPABILITY, NativeImport, NativeInstr, NativeLlmInput,
    NativeSymbol,
};
pub use obfuscators::{
    AMICE_XOR_KEY, CffUnflattenReport, ObfuscatorFamily, ObfuscatorHit, StringDecryptHit,
    XorStringHit, decrypt_strings_for_family, detect as detect_obfuscators,
    recover_amice_xor_strings, recover_obfuscxx_strings, recover_single_byte_xor_strings,
    strip_ollvm_bcf, undo_ollvm_substitution, unflatten_ollvm, unflatten_tigress,
};
pub use packers::aspack_unpack::{
    AspackRecovery, AspackReport, CarvedBlock as AspackCarvedBlock,
    RecoveredObject as AspackRecoveredObject, unpack_aspack,
};
pub use packers::loader_generators::{
    ByteRegion, DonutCompression, DonutConfig, DonutEntropy, DonutModuleType, LoaderArchitecture,
    LoaderConfig, LoaderFamily, LoaderFingerprint, LoaderInspection, LoaderRecovery, LoaderVariant,
    RecoveryField, SrdiConfig, WrappedModuleFormat, WrappedModuleMetadata, fingerprint_loader,
    recover_loader,
};
pub use packers::overlay::{
    ArchiveKind as OverlayArchiveKind, CertType as OverlayCertType, OverlayClass, OverlaySegment,
    PeOverlayReport, analyze_pe_overlay, carve_overlay as carve_pe_overlay, compute_image_end,
    normalize_pe, route_overlay_archive,
};
pub use packers::pecompact_unpack::{
    CarvedCode as PecompactCarvedCode, PecompactRecovery, PecompactReport, unpack_pecompact,
};
pub use packers::section_recovery::{SectionRecoveryReport, section_recovery_report};
pub use packers::yodas_crypter::{
    RecoveredSection as YodasRecoveredSection, SectionRecovery as YodasSectionRecovery,
    YodasCrypterReport, unpack_yodas_crypter,
};
pub use packers::yodas_emulated_unpack::{
    DESCRIPTOR_TABLE_TAG as YODAS_DESCRIPTOR_TABLE_TAG, YODAS_DELTA_PROLOGUE, YODAS_STUB_SECTION,
    YodasEmulatedUnpack, YodasSectionDescriptor, YodasStubProgress, unpack_yodas_emulated,
};
pub use packers::yodas_protector_phase2::{
    StubProgress as YodasProtectorStubProgress, YodasProtectorPhase2, unpack_yodas_protector_phase2,
};
pub use packers::{
    AsProtectLayout, AsProtectRecovery, AspackPhaseTwoOutput, CHAIN_SIGNATURES,
    CarvedSectionArtifact, CarvedVmpSection, ChainDetection, ChainSignature, Confidence,
    Detection as PackerDetection, DisFilterStreamSizes, FsgImport, FsgUnpackOutput,
    KkrunchyByteRecoveryReport, KkrunchyClassicStream, KkrunchyEmulatedUnpackOutput,
    KkrunchyEmulationSnapshot, KkrunchyEmulator, KkrunchyHeaderInfo, KkrunchyPhaseTwoOutput,
    KkrunchyUnpackOutput, KkrunchyVariant, MewEmulatedOutput, MewImport, MewLeadingChunk,
    MewLzmaProps, MewRebuiltImage, MewRecovery, MewUnpackOutput, MorphineLayout, MorphineRecovery,
    MpressImport, MpressInfo, MpressRecoveryStatus, MpressUnpackOutput, NPackLayout, NPackRecovery,
    NeoLiteLayout, NeoLiteRecovery, NspackEmulatedReport, NspackLayout, NspackRecoveryStatus,
    NspackSection, NspackUnpackReport, OreansProduct, Packer, PecompactPhaseTwoOutput,
    PetitePhase2EmulatedOutput, PetiteUnpackReport, PetiteUnpackResult, PolyCryptorLayout,
    PolyCryptorRecovery, RecoveredImage, RecoveredImport, RecoveredImportFn,
    RecoveredResource as NspackRecoveredResource,
    RecoveredSectionName as NspackRecoveredSectionName, RecoveryOracle, SectionPerms,
    SyntheticImport, ThemidaCarve, UnbindReport, UnpackerStatus, UpxMethod, UpxPackHeader,
    UpxUnpackOutput, VmProtectCarve, WarzoneCrypterLayout, WarzoneCrypterRecovery,
    asprotect_layout, build_loaded_image, carve_themida, carve_vmprotect, compute_byte_recovery,
    decompress_kkrunchy_classic, detect as detect_packers, detect_packer_chain, dis_filter,
    dis_unfilter, fingerprint_chain, locate_classic_stream, morphine_layout, neolite_layout,
    npack_layout, parse_kkrunchy_header, parse_nspack_layout, polycryptor_layout, recover_detected,
    unbind_pe, unpack_aspack_phase2_emulated, unpack_asprotect, unpack_asprotect_emulated,
    unpack_fsg, unpack_kkrunchy, unpack_kkrunchy_emulated, unpack_kkrunchy_phase2_emulated,
    unpack_mew, unpack_mew_emulated, unpack_mew_rebuilt, unpack_morphine, unpack_morphine_emulated,
    unpack_mpress, unpack_neolite, unpack_neolite_emulated, unpack_npack, unpack_npack_emulated,
    unpack_nspack, unpack_nspack_emulated, unpack_nspack_emulated_with_baseline,
    unpack_nspack_emulated_with_baseline_raw, unpack_pecompact_phase2_emulated, unpack_petite,
    unpack_petite_phase2_emulated, unpack_petite_with_report, unpack_polycryptor,
    unpack_polycryptor_emulated, unpack_upx, unpack_warzone_crypter,
    unpack_warzone_crypter_emulated, warzone_crypter_layout,
};
pub use pass::analyze_deobf_report;
pub use patch::{
    AppliedEdit, PatchEdit, PatchReport, apply_patches, apply_patches_reported, default_nop_fill,
};
pub use pdb_cxx::{
    BitfieldSpec, EmittedBase, EmittedEnum, EmittedEnumerator, EmittedField, EmittedFunction,
    EmittedGlobal, EmittedTypedef, EmittedUdt, PdbCxxReconstruction, RejectReason, RejectedType,
    UdtTagKeyword, perturb_first_offset, reconstruct_pdb_cxx, render_static_assert_tu,
};
pub use plt_resolve::{
    ImportStub, TailCall, TailCallKind, classify_tail_calls, resolve_elf_plt_imports,
    resolve_pe_iat_imports,
};
pub use provenance_header::{
    c_lifted_header, cpp_lifted_header, render_c_with_header, render_cpp_with_header,
    render_rust_with_header, rust_lifted_header,
};
pub use pseudo_c::{
    Abi as PseudoAbi, CallSiteReturnProof, CallSiteSignatureProof, FpConstant, JumpTable,
    LeafRecovery, ProgramFunction, RecoveredFunction, RecoveredProgram, Reg as PseudoReg,
    ResolvedCall, ScalarType as PseudoScalarType, SretReturn, UnrecoveredFunction,
    callee_int_arity, recover_aarch64_function, recover_aarch64_function_with_calls,
    recover_aarch64_function_with_image, recover_aarch64_program, recover_leaf_function,
    recover_leaf_function_abi, recover_leaf_function_const_abi, recover_leaf_function_in_object,
    recover_leaf_function_rust_abi, recover_leaf_function_switch_abi,
    recover_leaf_function_switch_const_abi, recover_leaf_function_with_calls, recover_program,
    recover_vectorized_reduction, resolved_int_arity_in_object,
};
pub use rust_recovery::{
    AuditableCrate, AuditableSbom, DemangleScheme, DemangledSymbol, EnumDiscriminant,
    MonomorphizationGroup, PanicKind, PanicSignature, VtableEntry, demangle as demangle_rust,
    detect_panic_signatures, group_monomorphizations, parse_auditable_section,
    recover_enum_discriminants, recover_trait_vtables,
};
pub use sig_engine::{
    CompilerFamily, CompilerIdentity, Confidence as SigConfidence, EntropyBand, EntropyProfile,
    InstallerFamily, LinkerFamily, LinkerIdentity, PackerFamily, ProtectorFamily, SigKind,
    SigMatch, SigReport, StructClass, StructFamily, StructFinding, Target as SigTarget,
    analyze as analyze_signatures, detect_format as sig_detect_format,
    struct_findings as native_struct_findings,
};
#[cfg(feature = "chain")]
pub use sig_engine::{PASS_ID as SIG_ENGINE_PASS_ID, SigEngineDetector};
pub use sigmaker::{SigmakerOptions, Signature, SignatureByte, make_signature};
pub use similarity::extract_function_features;
pub use stack_frame::{
    FrameLayout, STACK_FRAME_SCHEMA, StackFrameReport, StackSlot, recover_stack_frames,
};
pub use stack_string::{
    ReadOnlyWindow as StackStringRodataWindow, ReassembledStackString, StackBase,
    reassemble_stack_strings, reassemble_stack_strings_with_rodata,
};
pub use stream_disasm::{
    RipRef, StreamDisasmLimits, StreamDisasmStats, scan_rip_relative_refs, stream_disasm_x86,
};

pub use vm_devirt::{
    BinKind as VmBinKind, CmpKind as VmCmpKind, DevirtError, DevirtReport, DispatchKind,
    HandlerSemantics, LiftedProgram, MicroOp, StructuredNode, VmBlock, VmCfg, VmDetection, VmInsn,
    VmStructure, devirtualize as devirtualize_vm,
};

pub use entropy::{
    ENTROPY_WINDOW_4K, EntropyBlock, HIGH_ENTROPY_THRESHOLD, locate_high_entropy,
    shannon_entropy_bits, windowed_entropy,
};
pub use entropy_viz::{
    ByteHistogram, EntropySvgOptions, HighEntropyRun, SectionSpan, byte_histogram, entropy_color,
    entropy_heat_strip, entropy_sparkline, high_entropy_runs, histogram_ascii_16,
    render_entropy_svg,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[must_use]
pub const fn version() -> &'static str {
    VERSION
}
