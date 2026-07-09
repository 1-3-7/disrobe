#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![allow(
    clippy::match_same_arms,
    clippy::collapsible_match,
    clippy::collapsible_if,
    clippy::redundant_pub_crate
)]

pub(crate) fn push_string_fmt(out: &mut String, args: std::fmt::Arguments<'_>) {
    match std::fmt::write(out, args) {
        Ok(()) => {}
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

pub(crate) fn push_string_line(out: &mut String, args: std::fmt::Arguments<'_>) {
    push_string_fmt(out, args);
    out.push('\n');
}

mod analyze;
mod cfg;
#[cfg(feature = "chain")]
pub mod chain_detector;
mod component;
mod component_lift;
mod custom_page_sizes;
pub(crate) mod debug;
mod detect;
#[cfg(feature = "dwarf")]
pub mod dwarf;
mod eh;
mod error;
pub mod format_wire;
mod function_refs;
mod gc_extern;
mod gc_hir;
mod gc_types;
mod js_string_builtins;
mod lift;
mod lift_c;
mod lift_module_faithful;
mod lift_wat;
#[cfg(feature = "llm-metadata")]
pub mod llm;
mod memory64;
pub mod name_recovery;
mod obfuscators;
mod op_lift;
mod op_names;
pub mod pass;
mod provenance_header;
pub mod recover;
mod signature;
mod simd;
pub mod sourcemap;
mod ssa;
mod stack_switching;
mod structure;
mod structured;
mod tail_call;
mod threads;
mod types;

pub use analyze::{ModuleSummary, NameInfo, analyze_module};
pub use cfg::{BlockId, CfgBlock, FunctionCfg, TerminatorKind, build_function_cfg};
pub use custom_page_sizes::{
    CustomPageSizeRecord, CustomPageSizeReport, DEFAULT_PAGE_SIZE_BYTES, DEFAULT_PAGE_SIZE_LOG2,
    scan_custom_page_sizes,
};
pub use detect::{WasmDetection, WasmObfuscator, detect};
pub use eh::{
    EhConstruct, EhFunctionSummary, EhModuleSummary, EhTagSummary, lift_tag_to_rust_result,
    scan_module as scan_module_eh,
};
pub use error::{Error, Result};
pub use format_wire::{
    format_c as format_c_lifted, format_rust as format_rust_lifted,
    format_typescript as format_typescript_lifted, format_wat,
};
pub use function_refs::{FuncRefOpKind, FuncRefOpRecord, FuncRefReport, scan_function_refs};
pub use gc_extern::{ExternConvKind, ExternConvOpRecord, GcExternReport, scan_gc_extern};
pub use js_string_builtins::{
    JS_STRING_NAMESPACE, JsStringBuiltin, JsStringImport, JsStringReport, TEXT_DECODER_NAMESPACE,
    TEXT_ENCODER_NAMESPACE, scan_js_string_builtins,
};
pub use lift::{
    CalleeNames, LiftCoverage, LiftResult, LiftTarget, lift_function_body, rust_runtime_prelude,
    typescript_runtime_prelude,
};
pub use lift_c::c_runtime_prelude;
pub use lift_module_faithful::lift_module_faithful_wat;
pub use lift_wat::{lift_module_to_wat, wat_module_header};
pub use memory64::{MemoryRecord, MemoryReport, scan_memories};
#[cfg(feature = "dwarf")]
pub use name_recovery::attach_dwarf_names;
pub use name_recovery::{NameRecoveryStats, attach_sourcemap_names};
pub use obfuscators::{
    CanonicalizeStats, CrypticBytesDetection, CrypticBytesPeel, DataDecryptStats,
    DeadFunctionStats, DefragStats, DemangleStats, DispatcherInfo, HeapRegion, IntegrityCfgStats,
    IntegrityStripStats, MbaSsaStats, NameStrategy, OpaquePredStats, ProbeSource, ReinlineStats,
    StubInfo, UnflattenStats, UnresolvedReason, UnresolvedStub, UnwrapReport, UnwrappedSegment,
    WobfuscatorTable, canonicalize_substitutions, classify_export_strategy, decrypt_data_sections,
    defragment, demangle_names, demangle_symbol, detect_cryptic_bytes, detect_decrypt_stubs,
    detect_dispatcher, eliminate_integrity_guards, extract_optable, kill_opaque_predicates,
    lift_op_to_rust_fn, peel_cryptic_bytes, recover_heap_regions, reinline_imported_ops,
    simplify_mba, strip_dead_functions, strip_integrity_imports, unflatten,
    unflatten_to_fixed_point, unwrap_decryption,
};
pub use pass::{WasmDeobLegacyPass, WasmPassReport};
pub use provenance_header::{
    c_lifted_header, render_c_lifted_with_header, render_rust_lifted_with_header,
    render_ts_lifted_with_header, render_wat_decompiled_with_header, rust_lifted_header,
    ts_lifted_header, wat_decompiled_header,
};
pub use recover::{CollatzWitness, RecoveredModule, RecoveryReport, recover_module};
pub use signature::{
    ExportAlias, FunctionSig, ModuleSignatures, count_defined_function_bodies,
    dedup_export_aliases, dwarf_local_names, extract_signatures, signatures_or_placeholders,
};
pub use simd::{SimdFlavor, SimdLane, SimdOpRecord, SimdReport, scan_simd};
pub use sourcemap::{
    SOURCE_MAPPING_URL_SECTION, Segment as SourceMapSegment, SourceMap, extract_source_mapping_url,
    parse_source_map,
};
pub use ssa::{
    BlockTarget, CallSignatures, ConstVal, GlobalSet, LocalId, OpKind, SideEffect, SsaBlock,
    SsaFunction, SsaMemArg, SsaTerm, SsaValue, UnOp, ValueDef, ValueId, build_ssa,
    build_ssa_with_calls, promote_locals_to_ssa,
};
pub use stack_switching::{
    ResumeHandlerRecord, StackSwitchOpKind, StackSwitchOpRecord, StackSwitchReport,
    scan_stack_switching,
};
pub use structure::{StructuredFunction, StructuredNode, reloop_inverse};
pub use structured::rust_module_decls;
pub use tail_call::{TailCallKind, TailCallRecord, TailCallReport, scan_tail_calls};
pub use threads::{AtomicOpKind, AtomicOpRecord, SharedMemoryRecord, ThreadsReport, scan_threads};
pub use types::{
    AccessPattern, BaseOrigin, FieldRecord, LoadKind, NamedField, NamedType, RecoveredType,
    RecoveredTypes, StoreKind, WasmValType, classify_aggregates, synthesize_named_types,
};

pub use component::{
    ComponentClassification, ComponentManifest, EmbeddedModule, classify_preamble,
    parse_component_manifest,
};
pub use component_lift::{
    ComponentBindingItem, ComponentBindingKind, ComponentBindings, lift_component_manifest,
};
pub use gc_hir::{GcHirArray, GcHirField, GcHirModule, GcHirStruct, GcHirTy, lift_gc_module};
pub use gc_types::{
    ArrayTypeRecord, GcFieldRecord, GcRefKind, GcStorageKind, GcTypeGraph, StructTypeRecord,
    TypeIdx, recover_gc_types,
};

#[must_use]
pub fn recover_types(ssa: &SsaFunction) -> Vec<(BaseOrigin, RecoveredType)> {
    let patterns: Vec<AccessPattern> = build_access_patterns(ssa);
    classify_aggregates(&patterns)
}

pub fn recover_types_full(bytes: &[u8], ssa: &SsaFunction) -> Result<RecoveredTypes> {
    let aggregates: Vec<(BaseOrigin, RecoveredType)> = recover_types(ssa);
    let gc_graph: GcTypeGraph = recover_gc_types(bytes)?;
    Ok(RecoveredTypes::new(aggregates, gc_graph))
}

fn build_access_patterns(ssa: &SsaFunction) -> Vec<AccessPattern> {
    let mut out: Vec<AccessPattern> = Vec::new();
    for block in &ssa.blocks {
        for vid in &block.instrs {
            let Some(def): Option<&ValueDef> = ssa.values.get(vid.0 as usize) else {
                continue;
            };
            if let ValueDef::Load {
                addr, memarg, kind, ..
            } = def
            {
                let base_origin: BaseOrigin = classify_base_origin(*addr, ssa);
                let is_indexed: bool = address_is_indexed(*addr, ssa);
                let width: u32 = load_kind_width(*kind);
                out.push(AccessPattern {
                    load_kind: Some(*kind),
                    store_kind: None,
                    width,
                    alignment: alignment_from_exponent(memarg.align),
                    offset_class: i32::try_from(memarg.offset).unwrap_or(i32::MAX),
                    base_origin,
                    is_indexed,
                });
            }
        }
        for store in &block.stores {
            let base_origin: BaseOrigin = classify_base_origin(store.addr, ssa);
            let is_indexed: bool = address_is_indexed(store.addr, ssa);
            let width: u32 = store_kind_width(store.kind);
            out.push(AccessPattern {
                load_kind: None,
                store_kind: Some(store.kind),
                width,
                alignment: alignment_from_exponent(store.memarg.align),
                offset_class: i32::try_from(store.memarg.offset).unwrap_or(i32::MAX),
                base_origin,
                is_indexed,
            });
        }
    }
    out
}

fn alignment_from_exponent(align: u8) -> u32 {
    1u32.checked_shl(u32::from(align))
        .map_or(u32::MAX, |value: u32| value)
}

const MAX_ORIGIN_DEPTH: u32 = 1024;

fn classify_base_origin(v: ValueId, ssa: &SsaFunction) -> BaseOrigin {
    classify_base_origin_depth(v, ssa, 0)
}

fn classify_base_origin_depth(v: ValueId, ssa: &SsaFunction, depth: u32) -> BaseOrigin {
    if depth >= MAX_ORIGIN_DEPTH {
        return BaseOrigin::Unknown;
    }
    let Some(def): Option<&ValueDef> = ssa.values.get(v.0 as usize) else {
        return BaseOrigin::Unknown;
    };
    match def {
        ValueDef::Param(_, idx) => BaseOrigin::Param(u32::from(*idx)),
        ValueDef::Const(_) => BaseOrigin::Global(0),
        ValueDef::GlobalGet { global, .. } => BaseOrigin::Global(*global),
        ValueDef::Op { args, .. } => args.first().copied().map_or(BaseOrigin::Unknown, |a| {
            classify_base_origin_depth(a, ssa, depth + 1)
        }),
        ValueDef::Unary { arg, .. } => classify_base_origin_depth(*arg, ssa, depth + 1),
        ValueDef::Load { addr, .. } => {
            let inner: BaseOrigin = classify_base_origin_depth(*addr, ssa, depth + 1);
            if matches!(inner, BaseOrigin::Unknown) {
                BaseOrigin::Heap
            } else {
                inner
            }
        }
        ValueDef::Phi { .. }
        | ValueDef::Select { .. }
        | ValueDef::Call { .. }
        | ValueDef::CallIndirect { .. }
        | ValueDef::MemorySize { .. }
        | ValueDef::MemoryGrow { .. } => BaseOrigin::Unknown,
    }
}

fn address_is_indexed(v: ValueId, ssa: &SsaFunction) -> bool {
    address_is_indexed_depth(v, ssa, 0)
}

fn address_is_indexed_depth(v: ValueId, ssa: &SsaFunction, depth: u32) -> bool {
    if depth >= MAX_ORIGIN_DEPTH {
        return false;
    }
    let Some(def): Option<&ValueDef> = ssa.values.get(v.0 as usize) else {
        return false;
    };
    match def {
        ValueDef::Op { kind, args, .. } => {
            matches!(kind, OpKind::I32Shl | OpKind::I32Mul)
                || args
                    .iter()
                    .any(|a| address_is_indexed_depth(*a, ssa, depth + 1))
        }
        _ => false,
    }
}

const fn load_kind_width(k: LoadKind) -> u32 {
    match k {
        LoadKind::I32_8U | LoadKind::I32_8S | LoadKind::I64_8U | LoadKind::I64_8S => 1,
        LoadKind::I32_16U | LoadKind::I32_16S | LoadKind::I64_16U | LoadKind::I64_16S => 2,
        LoadKind::I32 | LoadKind::F32 | LoadKind::I64_32U | LoadKind::I64_32S => 4,
        LoadKind::I64 | LoadKind::F64 => 8,
    }
}

const fn store_kind_width(k: StoreKind) -> u32 {
    match k {
        StoreKind::I32_8 | StoreKind::I64_8 => 1,
        StoreKind::I32_16 | StoreKind::I64_16 => 2,
        StoreKind::I32 | StoreKind::F32 | StoreKind::I64_32 => 4,
        StoreKind::I64 | StoreKind::F64 => 8,
    }
}

#[cfg(feature = "llm-metadata")]
pub use llm::{METADATA_CAPABILITY as WASM_METADATA_CAPABILITY, WasmFn, WasmImport, WasmLlmInput};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use smallvec::smallvec;
    use wasmparser::ValType;

    use super::*;

    #[test]
    fn recover_types_clamps_oversized_alignment_exponent() {
        let ssa: SsaFunction = SsaFunction {
            values: vec![
                ValueDef::Param(BlockId(0), 0),
                ValueDef::Load {
                    addr: ValueId(0),
                    memarg: SsaMemArg {
                        align: 40,
                        offset: 0,
                        memory: 0,
                    },
                    kind: LoadKind::I32,
                    ty: ValType::I32,
                },
            ],
            blocks: vec![SsaBlock {
                id: BlockId(0),
                params: smallvec![],
                instrs: vec![ValueId(1)],
                stores: Vec::new(),
                global_sets: Vec::new(),
                terminator: SsaTerm::Return(smallvec![]),
                preds: Vec::new(),
            }],
            entry: BlockId(0),
        };
        let recovered: Vec<(BaseOrigin, RecoveredType)> = recover_types(&ssa);
        assert_eq!(recovered.len(), 1);
    }
}
