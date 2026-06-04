#![forbid(unsafe_code)]
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

#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod cordova;
pub mod error;
pub mod flutter;
pub mod hermes;
pub mod ios;
pub mod nativescript;
pub mod pass;
pub mod provenance_header;
pub mod react_native;
pub mod xamarin;

pub use cordova::{
    WebviewAsset, WebviewBundleKind, WebviewExtractionReport, extract_webview_bundle,
    is_webview_asset, mime_hint_for,
};
pub use error::{Error, Result};
pub use flutter::{
    DART_ISOLATE_DATA_SYMBOL, DART_ISOLATE_INSTR_SYMBOL, DART_SNAPSHOT_MAGIC, DART_VM_DATA_SYMBOL,
    DART_VM_INSTR_SYMBOL, DartAotDecompile, DartFunctionBoundary, DartFunctionSkeleton,
    DartNameKind, DartProgramSkeleton, DartSnapshotHeader, DartSnapshotKind, DartStaticRecovery,
    DemangledName, FlutterApkLayout, FlutterObfuscationMap, ImageHeader, LibAppLayout,
    SnapshotSection, build_program_skeleton as build_dart_program_skeleton, decompile_dart_aot,
    decompile_libapp_so, demangle as demangle_dart_name,
    demangle_qualified as demangle_dart_qualified, parse_dart_snapshot, parse_flutter_apk,
    parse_flutter_obfuscation_map, parse_image_header as parse_dart_image_header, parse_libapp_so,
    recover_dart_static, static_recovery_fraction as dart_static_recovery_fraction,
};
pub use hermes::{
    BigIntTableEntry, BufferKind, DecompileReport, DecompiledFunction, DisassemblyReport,
    FunctionDisasm, HERMES_MAGIC, HERMES_MAGIC_LE_BYTES, HERMES_MAX_VERSION, HERMES_MIN_VERSION,
    HermesHeader, HermesModule, HermesStringKind, JsLiftReport, LiteralValue, RecoveredRegExp,
    RegExpTableEntry, SmallFunctionHeader, bigint_literal as hermes_bigint_literal,
    builtin_name as hermes_builtin_name, decode_literals as decode_hermes_literals,
    decompile_function as decompile_hermes_function, decompile_module as decompile_hermes_module,
    disassemble as disassemble_hermes, disassemble_function_instructions as hermes_disasm_function,
    header_size_for_version, is_template_object_builtin,
    lift_to_js_surface as hermes_lift_to_js_surface, parse as parse_hermes_module,
    parse_header as parse_hermes_header, recover_bigints as recover_hermes_bigints,
    recover_regexps as recover_hermes_regexps,
};
pub use ios::{
    FatArchEntry, IpaEntry, IpaExtractionReport, MACHO_FAT_MAGIC_64_BE, MACHO_FAT_MAGIC_BE,
    MachOFatReport, extract_ipa, extract_ipa_file_bytes, walk_macho_fat,
};
pub use nativescript::{NativeScriptBundle, NativeScriptReport, extract_nativescript_bundle};
pub use pass::{DetectedKind, HermesSummary, MobilePass, MobilePassOutput, detect_kind};
pub use provenance_header::{
    dart_decompiled_header, hermes_disasm_header, hermes_lifted_to_js_header,
    render_dart_with_header, render_hermes_disasm_with_header, render_hermes_lifted_with_header,
    render_rn_bundle_with_header, rn_bundle_extracted_header,
};
pub use react_native::{
    RnBundleEntry, RnBundleFormat, RnBundlePlatform, RnExtractionReport, classify_bundle_path,
    detect_bundle_format, extract_from_apk_or_ipa,
};
pub use xamarin::{
    AssemblyStoreHeader, XAMARIN_ASSEMBLY_STORE_V2_MAGIC, XamarinAssembly, XamarinKind,
    XamarinReport, extract_xamarin_bundle, parse_assembly_store_header,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[must_use]
pub fn version() -> &'static str {
    VERSION
}
