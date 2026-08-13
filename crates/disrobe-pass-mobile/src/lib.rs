#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![allow(
    clippy::redundant_pub_crate,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::needless_type_cast,
    clippy::manual_is_multiple_of,
    clippy::missing_const_for_fn,
    clippy::option_if_let_else,
    clippy::single_match_else,
    clippy::match_same_arms,
    clippy::map_unwrap_or,
    clippy::unreadable_literal
)]

use std::io::Read as _;

pub mod android_attrs;
pub mod apk_recon;
pub mod apk_signing;
pub mod arsc;
pub mod axml;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod cordova;
pub(crate) mod debug;
pub mod error;
pub mod flutter;
pub mod hermes;
pub mod ios;
pub mod nativescript;
pub mod pass;
pub mod provenance_header;
pub mod react_native;
pub mod res_decode;
pub mod xamarin;

pub use android_attrs::framework_attr_name;
pub use apk_recon::{
    ApkReconReport, AppProtector, ArscReconSummary, NativeLibrary, ProtectorArtifact,
    ProtectorArtifactKind, ProtectorWall, ResolvedResource, RouteTarget, RoutedChild,
    SurfacedEndpoint, SurfacedSecret, analyze as analyze_apk_recon,
};
pub use apk_signing::{
    APK_SIG_BLOCK_MAGIC, APK_SIGNATURE_SCHEME_V2_BLOCK_ID, APK_SIGNATURE_SCHEME_V3_1_BLOCK_ID,
    APK_SIGNATURE_SCHEME_V3_BLOCK_ID, ApkSigningBlockReport, SchemeBlock, SignatureAlgorithm,
    SignatureScheme, SignerCertificate, SignerRecord, VERITY_PADDING_BLOCK_ID,
    parse as parse_apk_signing_block,
};
pub use arsc::{ArscEntry, ArscPackageSummary, ArscResources, parse as parse_arsc};
pub use axml::{
    AndroidManifestSummary, AxmlAttribute, AxmlDocument, AxmlElement, ComponentSummary,
    NamespaceBinding, parse as parse_axml, summarise_manifest,
};
pub use cordova::{
    WebviewAsset, WebviewBundleKind, WebviewExtractionReport, extract_webview_bundle,
    is_webview_asset, mime_hint_for,
};
pub use error::{Error, Result};
pub use flutter::{
    AotLiftReport, Arm64Disassembly, Arm64FlowKind, Arm64Function, Arm64Instruction,
    Arm64TraversalReport, Arm64Unresolved, Arm64UnresolvedKind, CidTableMatch,
    ClusterFramingStatus, DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_FEATURES,
    DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_LAYOUT, DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES,
    DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT, DART_ISOLATE_DATA_SYMBOL, DART_ISOLATE_INSTR_SYMBOL,
    DART_KERNEL_MAGIC, DART_POOL_ELEMENT_BASE_BYTES, DART_SNAPSHOT_MAGIC, DART_VM_DATA_SYMBOL,
    DART_VM_INSTR_SYMBOL, DartAotDecompile, DartCallKind, DartCallSite, DartCheckKind,
    DartCidTable, DartClassBodyLayout, DartClassEntry, DartClusterBodyEntry, DartClusterBodyKind,
    DartClusterRole, DartClusterSchemaReport, DartDeclarationBodyLayouts, DartElidedCheck,
    DartFieldBodyLayout, DartFunctionBodyLayout, DartFunctionBoundary, DartFunctionSkeleton,
    DartFunctionSymbol, DartGraphAttributionResidue, DartGraphBlobSizes, DartGraphClusterSummary,
    DartGraphDeclaredObjects, DartGraphInventoryCounts, DartGraphLimits, DartGraphNameMode,
    DartGraphObfuscationHint, DartGraphRecoveryOptions, DartGraphRecoveryReport,
    DartGraphRecoveryStatus, DartGraphSnapshotSummary, DartKernel, DartKernelDecompile,
    DartLibAppRecovery, DartLibraryBodyLayout, DartLiftedFunction, DartMethodEntry, DartNameKind,
    DartNameSource, DartObservedCluster, DartPatchClassBodyLayout, DartPinnedClassInventory,
    DartPinnedFieldInventory, DartPinnedInventory, DartPinnedLayout, DartPinnedLibraryInventory,
    DartPinnedMethodInventory, DartPoolLiteral, DartPoolLiteralKind, DartPoolLoadForm, DartPoolRef,
    DartPoolString, DartPoolTable, DartPoolTableStats, DartProgramSkeleton, DartReadStream,
    DartRecoveredFunction, DartRecoveryCounts, DartSnapshotFraming, DartSnapshotHeader,
    DartSnapshotKind, DartSnapshotStructure, DartStaticRecovery, DartStringPool, DartStringRole,
    DartUnliftedArm64, DemangledName, DispatchSite, FlutterApkLayout, FlutterObfuscationMap,
    ImageHeader, KernelClass, KernelLibrary, KernelProcedure, KernelProcedureKind, KernelSource,
    LibAppLayout, ObjectPoolReferenceMap, PINNED_DART_GRAPH_LAYOUTS, PoolSlotUse, PredefinedClass,
    SnapshotSection, attach_cluster_schema, build_program_skeleton as build_dart_program_skeleton,
    cid_matches_version, cid_table, decompile_dart_aot, decompile_dart_kernel, decompile_libapp_so,
    decompile_libapp_so_recovery, decompile_libapp_so_structured, demangle as demangle_dart_name,
    demangle_qualified as demangle_dart_qualified,
    disassemble_function as disassemble_dart_function,
    disassemble_functions as disassemble_dart_functions, disassemble_libapp_so,
    has_pinned_dart_graph_layout, is_application_cid, is_dart_kernel,
    isolate_data_bytes as dart_isolate_data_bytes,
    isolate_instruction_bytes as dart_isolate_instruction_bytes, lift_dart_aot_functions,
    lift_libapp_aot, parse_dart_snapshot, parse_flutter_apk, parse_flutter_obfuscation_map,
    parse_image_header as parse_dart_image_header, parse_kernel as parse_dart_kernel,
    parse_libapp_so, parse_snapshot_framing, pinned_dart_graph_layout, predefined_classes,
    predefined_count, predefined_name, recover_dart_pinned_elf, recover_dart_pinned_standalone,
    recover_dart_snapshot_structure, recover_dart_snapshot_structure_with_symbols,
    recover_dart_static, recover_libapp, recover_object_pool_references, recover_string_pool,
    recovery_counts as dart_recovery_counts, resolve_pool_literals, traverse_arm64,
    vm_data_bytes as dart_vm_data_bytes, vm_instruction_bytes as dart_vm_instruction_bytes,
};
pub use hermes::{
    BigIntTableEntry, BufferKind, DeclineCount, DecompileReport, DecompiledFunction,
    DisassemblyReport, FunctionDisasm, HERMES_LIFT_VERSION, HERMES_LIFTED_VERSIONS, HERMES_MAGIC,
    HERMES_MAGIC_LE_BYTES, HERMES_MAX_VERSION, HERMES_MIN_VERSION, HermesExceptionEntry,
    HermesHeader, HermesModule, HermesStringKind, JsLiftReport, LiteralValue, OpcodeCount,
    RecoveredRegExp, RegExpTableEntry, SmallFunctionHeader, StructureDecline,
    bigint_literal as hermes_bigint_literal, builtin_name as hermes_builtin_name,
    decode_literals as decode_hermes_literals, decompile_function as decompile_hermes_function,
    decompile_module as decompile_hermes_module, disassemble as disassemble_hermes,
    disassemble_function_instructions as hermes_disasm_function,
    get_template_object_builtin as hermes_get_template_object_builtin, header_size_for_version,
    is_template_object_builtin, lift_to_js_surface as hermes_lift_to_js_surface,
    opcode_label as hermes_opcode_label, parse as parse_hermes_module,
    parse_header as parse_hermes_header, recover_bigints as recover_hermes_bigints,
    recover_regexp as recover_hermes_regexp, recover_regexps as recover_hermes_regexps,
};
pub use ios::{
    FatArchEntry, IpaEntry, IpaExtractionReport, MACHO_FAT_MAGIC_64_BE, MACHO_FAT_MAGIC_BE,
    MachOFatReport, extract_ipa, extract_ipa_file_bytes, walk_macho_fat,
};
pub use nativescript::{NativeScriptBundle, NativeScriptReport, extract_nativescript_bundle};
pub use pass::{
    AndroidDexEntry, AndroidDexReport, DetectedKind, HermesSummary, MobilePass, MobilePassOutput,
    detect_kind, extract_android_bundle_children, extract_android_dex_children,
};
pub use provenance_header::{
    dart_decompiled_header, hermes_disasm_header, hermes_lifted_to_js_header,
    render_dart_with_header, render_hermes_disasm_with_header, render_hermes_lifted_with_header,
    render_rn_bundle_with_header, rn_bundle_extracted_header,
};
pub use react_native::{
    RnBundleEntry, RnBundleFormat, RnBundlePlatform, RnExtractionReport, classify_bundle_path,
    detect_bundle_format, extract_from_apk_or_ipa,
};
pub use res_decode::{
    DecodedResXml, ReconstructedValuesFile, ResDecodeReport,
    decode_archive as decode_apk_resources, is_binary_xml_res_path, is_res_xml_magic,
};
pub use xamarin::{
    AssemblyStoreHeader, XAMARIN_ASSEMBLY_STORE_V2_MAGIC, XamarinAssembly, XamarinKind,
    XamarinReport, extract_xamarin_bundle, parse_assembly_store_header,
};

pub const ZIP_ENTRY_PREALLOC_CAP: usize = 64 << 20;
pub const ZIP_ENTRY_READ_CAP: usize = 512 << 20;
pub const ZIP_ENTRY_COUNT_CAP: usize = 65_536;
const ZIP_ENTRY_PREALLOC_CAP_U64: u64 = 64 << 20;
const ZIP_ENTRY_READ_CAP_U64: u64 = 512 << 20;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[must_use]
pub(crate) const fn capped_zip_entry_count(count: usize) -> usize {
    if count > ZIP_ENTRY_COUNT_CAP {
        ZIP_ENTRY_COUNT_CAP
    } else {
        count
    }
}

pub(crate) fn checked_zip_entry_count(count: usize) -> Result<usize> {
    if count > ZIP_ENTRY_COUNT_CAP {
        return Err(Error::Zip(format!(
            "zip archive declares {count} entries, exceeding the {ZIP_ENTRY_COUNT_CAP} entry cap"
        )));
    }
    Ok(count)
}

pub(crate) fn read_zip_file_bounded(file: zip::read::ZipFile<'_>, entry: &str) -> Result<Vec<u8>> {
    let declared: u64 = file.size();
    if declared > ZIP_ENTRY_READ_CAP_U64 {
        return Err(Error::Zip(format!(
            "zip entry {entry} declared size {declared} exceeds the {ZIP_ENTRY_READ_CAP} byte decompression cap"
        )));
    }
    let capacity_u64: u64 = declared.min(ZIP_ENTRY_PREALLOC_CAP_U64);
    let capacity: usize = usize::try_from(capacity_u64).map_err(|_| {
        Error::Zip(format!(
            "zip entry {entry} declared size {declared} is not addressable"
        ))
    })?;
    let read_limit: u64 = ZIP_ENTRY_READ_CAP_U64
        .checked_add(1)
        .ok_or_else(|| Error::Zip("zip entry read cap overflow".to_owned()))?;
    let mut buf: Vec<u8> = Vec::with_capacity(capacity);
    let read: usize = file.take(read_limit).read_to_end(&mut buf)?;
    let read_u64: u64 = u64::try_from(read)
        .map_err(|_| Error::Zip(format!("zip entry {entry} read size is not addressable")))?;
    if read_u64 > ZIP_ENTRY_READ_CAP_U64 {
        return Err(Error::Zip(format!(
            "zip entry {entry} exceeds the {ZIP_ENTRY_READ_CAP} byte decompression cap"
        )));
    }
    Ok(buf)
}

#[must_use]
pub fn version() -> &'static str {
    VERSION
}
