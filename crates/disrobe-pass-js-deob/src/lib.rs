#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![allow(clippy::redundant_pub_crate)]
#[cfg(not(target_arch = "wasm32"))]
pub mod analysis;
mod bundle;
#[cfg(all(feature = "chain", not(target_arch = "wasm32")))]
pub mod chain_detector;
#[cfg(all(feature = "chain", not(target_arch = "wasm32")))]
pub use chain_detector::{JsCatalogEntry, JsObfDetector};
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod debug;
#[cfg(not(target_arch = "wasm32"))]
mod detect;
mod error;
#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::redundant_pub_crate)]
mod esoteric;
#[cfg(not(target_arch = "wasm32"))]
pub mod format_wire;
#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::redundant_pub_crate)]
mod js_string;
#[cfg(not(target_arch = "wasm32"))]
mod jsconfuser;
#[cfg(not(target_arch = "wasm32"))]
mod jscrambler;
#[cfg(not(target_arch = "wasm32"))]
mod jsobfu;
#[cfg(all(feature = "llm-metadata", not(target_arch = "wasm32")))]
pub mod llm;
#[cfg(not(target_arch = "wasm32"))]
mod mangled_names;
#[cfg(not(target_arch = "wasm32"))]
mod obfuscator_io;
#[cfg(not(target_arch = "wasm32"))]
pub mod protectors;
#[cfg(not(target_arch = "wasm32"))]
mod provenance_header;
#[cfg(not(target_arch = "wasm32"))]
mod rename;
#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::redundant_pub_crate)]
mod sandbox_guard;
#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::redundant_pub_crate)]
mod scan_utils;
mod source_text;
#[cfg(target_arch = "wasm32")]
use source_text as scan_utils;
#[cfg(not(target_arch = "wasm32"))]
mod string_array;
#[cfg(not(target_arch = "wasm32"))]
mod typescript;
#[cfg(not(target_arch = "wasm32"))]
mod unminify;
#[cfg(not(target_arch = "wasm32"))]
pub mod v8;

#[cfg(not(target_arch = "wasm32"))]
pub use analysis::{
    HotspotConfig, HotspotFinding, HotspotRule, HotspotSeverity, HotspotSpan, analyze_hotspots,
    analyze_hotspots_with,
};
#[cfg(not(target_arch = "wasm32"))]
pub use bundle::recover_deployed_source;
pub use bundle::{
    BundlerDetection, BundlerKind, ChunkAnnotation, ChunkKind, ChunkNode, DecodedInlineMap,
    DecodedMappings, DeployedRecovery, ExtractedModule, MappingSegment, MergedTreeRecovery,
    ModuleGraph, NoMapFallback, OriginalPosition, PositionResolver, RecoverOptions, RecoveredFile,
    RecoveredSourceMap, RecoveryReport, RenamedBinding, SourceCoverage, SourceMap, SourceMapEmit,
    SourceMapInfo, SourceMapLimits, SourceMapLocation, SourceTreeRecovery, SynthesizedSourceMap,
    UnbundleGraphResult, UnbundleLimits, UnbundleResult, ViteManifest, ViteManifestEntry,
    auto_unbundle, auto_unbundle_with_limits, build_id_to_path_map, decode_data_url_json,
    decode_inline_data_url, decode_mappings, decode_vlq, detect_amd, detect_browserify, detect_bun,
    detect_bundle, detect_esbuild, detect_parcel, detect_rolldown, detect_rollup, detect_systemjs,
    detect_turbopack, detect_vite, detect_webpack4, detect_webpack5, emit_source_maps,
    encode_mappings, find_source_map, merge_reports, parse_source_map, parse_source_map_v3,
    parse_source_map_with_limits, parse_vite_manifest, recover_source_map,
    recover_source_map_inline, recover_source_map_json, recover_source_tree_from_chunks,
    recover_source_tree_from_js, renamed_bindings, rewrite_modules, rewrite_requires,
    serialize_source_map, synthesize_from_modules, unbundle, unbundle_with_graph,
    unbundle_with_limits, unbundle_with_sourcemaps, vite_manifest_to_graph, write_graph,
    write_modules, write_recovered_sources, write_sourcemaps,
};
#[cfg(not(target_arch = "wasm32"))]
pub use detect::{Detection, JsObfuscator, detect};
pub use error::{Error, Result};
#[cfg(not(target_arch = "wasm32"))]
pub use esoteric::{
    AaEncodeDecode, AaEncodeDetection, AtobIndirectionResult, AtobIndirectionStats,
    EsotericClassification, EsotericFamily, EvalIndirectionResult, EvalIndirectionStats,
    JjEncodeDecode, JjEncodeDetection, JsFireTruckDecode, JsFireTruckDetection, JsFuckDecode,
    JsFuckDetection, PackerDecode, PackerDetection, classify as classify_esoteric, decode_aaencode,
    decode_jjencode, decode_jsfiretruck, decode_jsfuck, detect_aaencode, detect_jjencode,
    detect_jsfiretruck, detect_jsfuck, detect_packer, peel_atob_indirection, peel_eval_indirection,
    unpack_packer,
};
#[cfg(not(target_arch = "wasm32"))]
pub use format_wire::{format_javascript, format_typescript};
#[cfg(not(target_arch = "wasm32"))]
pub use jsconfuser::{
    AstScramblerResult, CalculatorReversalResult, CalculatorShape, DeadCodeReversalResult,
    DeobOptions, DeobOutput, DispatcherReversalResult, DispatcherShape, FlattenReversalResult,
    IntegrityReversalResult, IntegritySelfCheckResult, LockReversalResult, MovedDeclReversalResult,
    OpaqueReversalResult, PackingReversalResult, PredicateValue, RgfEvalReversalResult,
    RgfReversalResult, RgfShape, ShuffleReversalResult, StateSumReversalResult,
    StringCompressionResult, StringConcealResult, StringEncodingResult, VariableMaskingResult,
    deobfuscate_all, detect_calculator_shapes, detect_dispatcher_shapes, detect_rgf_shapes,
    recognize_predicate, reverse_ast_scrambler, reverse_calculator, reverse_dead_code,
    reverse_dispatcher, reverse_flatten, reverse_moved_declarations, reverse_opaque_predicates,
    reverse_packing, reverse_rgf, reverse_rgf_eval, reverse_shuffle, reverse_state_sum,
    reverse_string_compression, reverse_string_conceal, reverse_string_encoding,
    reverse_variable_masking, strip_integrity, strip_integrity_self_check, strip_locks,
};
#[cfg(not(target_arch = "wasm32"))]
pub use jscrambler::{
    CodeLockKind, IntegrityStripStats, JscramblerDetection, JscramblerOptions, JscramblerOutput,
    JscramblerTier, JscramblerTransform, TemplateOutput, TransformOpts as JscramblerTransformOpts,
    TransformOutput as JscramblerTransformOutput, TransformStats as JscramblerTransformStats,
    deobfuscate as deobfuscate_jscrambler, deobfuscate_template_advanced_obfuscation,
    deobfuscate_template_anti_tampering_and_debugging, deobfuscate_template_browser_lock,
    deobfuscate_template_date_lock, deobfuscate_template_dead_objects,
    deobfuscate_template_domain_lock, deobfuscate_template_light_obfuscation,
    deobfuscate_template_minification, deobfuscate_template_obfuscation,
    deobfuscate_template_os_lock, deobfuscate_template_self_defending,
    deobfuscate_template_self_healing, detect_free_tier, detect_full as detect_jscrambler_full,
    dispatch_reverse_strict as deobfuscate_jscrambler_transform_strict, strip_integrity_loops,
};
#[cfg(not(target_arch = "wasm32"))]
pub use jsobfu::{
    CharFoldStats, JsObfuDetection, JsObfuRecovery, JsObfuRewriteStats, detect_jsobfu,
    fold_char_constructors, recover as recover_jsobfu, rewrite_bracket_access,
    try_recover as try_recover_jsobfu,
};
#[cfg(not(target_arch = "wasm32"))]
pub use mangled_names::{
    Confidence as MangledNameConfidence, ConfidenceTier as MangledConfidenceTier,
    Context as MangledNameContext, ContextNameSource, CorpusEntry as MangledCorpusEntry,
    CorpusNameSource, HeuristicNameSource, NameDecision as MangledNameDecision,
    NameRegistry as MangledNameRegistry, NameSource, RestoreStats as MangledRestoreStats,
    RestoredName as MangledRestoredName, ScopeKey as MangledScopeKey,
    Suggestion as MangledSuggestion, SymbolRole as MangledSymbolRole,
};
#[cfg(not(target_arch = "wasm32"))]
pub use obfuscator_io::{
    DEFAULT_PASSES as OBFUSCATOR_IO_DEFAULT_PASSES,
    MAX_PASS_CEILING as OBFUSCATOR_IO_MAX_PASS_CEILING, ObfControl as ObfuscatorIoControl,
    ObfuscatorIoDetection, Options as ObfuscatorIoOptions, Output as ObfuscatorIoOutput,
    Preset as ObfuscatorIoPreset, deobfuscate as obfuscator_io_deobfuscate,
    deobfuscate_preset as obfuscator_io_deobfuscate_preset, detect as obfuscator_io_detect,
};
#[cfg(not(target_arch = "wasm32"))]
pub use protectors::{
    LegalStance, ProtectorDetection, ProtectorFamily, ProtectorOptions, ProtectorOutput,
    ProtectorStats,
    arxan::{
        FAMILY as ARXAN_FAMILY, LEGAL as ARXAN_LEGAL, deobfuscate as arxan_deobfuscate,
        detect as detect_arxan,
    },
    jsdefender::{
        FAMILY as JSDEFENDER_FAMILY, LEGAL as JSDEFENDER_LEGAL,
        deobfuscate as jsdefender_deobfuscate, detect as detect_jsdefender,
    },
    pace::{
        FAMILY as PACE_FAMILY, LEGAL as PACE_LEGAL, deobfuscate as pace_deobfuscate,
        detect as detect_pace, detect_only_report as pace_detect_only_report,
    },
};
#[cfg(not(target_arch = "wasm32"))]
pub use provenance_header::{
    js_decoded_header, js_deobfuscated_header, js_extracted_header,
    render_js_deobfuscated_with_header, render_ts_deobfuscated_with_header,
    render_v8_disasm_with_header, ts_deobfuscated_header, v8_bytecode_disasm_header,
    v8_bytecode_lifted_header,
};
#[cfg(not(target_arch = "wasm32"))]
pub use rename::{RenameStats, ScopeAwareStats, rename_hex_idents, rename_scope_aware};
#[cfg(not(target_arch = "wasm32"))]
pub use string_array::{StringArrayRecovery, recover as recover_string_array};
#[cfg(not(target_arch = "wasm32"))]
pub use typescript::{
    ClosureAdvancedReport, DtsCorpus, DtsModule, DtsReverseResult, DtsSymbol, DtsSymbolKind,
    InferredType, MangledCandidate, PresetEnvUndoResult, SourceMapEmitResult, TerserRestoreReport,
    TypeFlowReport, TypeRecoveryResult, TypeScriptEmitStats, analyze_flow, emit_ts_with_source_map,
    recover_types as recover_typescript, restore_terser_mangled, reverse_declarations,
    undo_closure_advanced, undo_preset_env,
};
#[cfg(not(target_arch = "wasm32"))]
pub use unminify::{
    AstPipeline, AstRuleId, AstUnminifyStats, UnminifyStats, try_unminify_ast, unminify,
    unminify_ast,
};

#[cfg(all(feature = "llm-metadata", not(target_arch = "wasm32")))]
pub use llm::{JsLlmInput, METADATA_CAPABILITY as JS_METADATA_CAPABILITY};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
