#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![allow(
    clippy::match_same_arms,
    clippy::collapsible_match,
    clippy::collapsible_if,
    clippy::redundant_pub_crate
)]

pub(crate) fn push_string_fmt(out: &mut impl std::fmt::Write, args: std::fmt::Arguments<'_>) {
    match std::fmt::write(out, args) {
        Ok(()) => {}
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

pub(crate) fn push_string_line(out: &mut impl std::fmt::Write, args: std::fmt::Arguments<'_>) {
    push_string_fmt(out, args);
    match out.write_char('\n') {
        Ok(()) => {}
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

mod analyze;
pub mod boundary_links;
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
pub mod fingerprint;
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
pub use boundary_links::{
    BOUNDARY_LINKS_SCHEMA_VERSION, BoundaryEvidence, BoundaryIdentitySource, BoundaryLanguage,
    BoundaryLink, BoundaryLinks, BoundaryLinksError, BoundarySymbol, BoundarySymbolKind,
    MAX_BOUNDARY_LINK_STRING_BYTES, MAX_BOUNDARY_LINKS, MAX_BOUNDARY_LINKS_JSON_BYTES,
};
pub use cfg::{BlockId, CfgBlock, FunctionCfg, TerminatorKind, build_function_cfg};
pub use custom_page_sizes::{
    CustomPageSizeRecord, CustomPageSizeReport, DEFAULT_PAGE_SIZE_BYTES, DEFAULT_PAGE_SIZE_LOG2,
    scan_custom_page_sizes,
};
pub use detect::{
    WasmDetection, WasmFamilySupport, WasmObfuscator, WasmPipelineSupport, WasmRecovery,
    WasmTransformSupport, detect,
};
pub use eh::{
    EhConstruct, EhFunctionSummary, EhModuleSummary, EhTagSummary, lift_tag_to_rust_result,
    scan_module as scan_module_eh,
};
pub use error::{AtomicMemoryRefusal, Error, Result};
pub use fingerprint::{
    DEFAULT_FUZZY_THRESHOLD, DEFAULT_MIN_FUZZY_OPS, FingerprintDb, FunctionFingerprint,
    FunctionMatch, MINHASH_WIDTH, MatchConfig, MatchTier, NGRAM_WINDOW, canonical_label,
    fingerprint_module, strip_name_section,
};
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
    CalleeNames, DEFAULT_MODULE_SOURCE_LIMIT_BYTES, LiftCoverage, LiftResult, LiftTarget,
    ModuleSourceLift, TypeScriptModuleLift, lift_function_body, lift_module_source,
    lift_module_source_with_limit, rust_runtime_prelude, try_lift_function_from_module,
    try_lift_functions_from_module, try_lift_typescript_module, typescript_runtime_prelude,
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
    AccessPattern, BaseOrigin, FieldRecord, LoadKind, NamedField, NamedType, PointerType,
    RecoveredStorageType, RecoveredType, RecoveredTypes, ScalarIntType, Signedness,
    SignednessReport, StoreKind, TypeRecoveryRefusal, WasmValType, classify_aggregates,
    recover_signedness, synthesize_named_types,
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

pub fn recover_types(
    ssa: &SsaFunction,
) -> std::result::Result<Vec<(BaseOrigin, RecoveredType)>, TypeRecoveryRefusal> {
    let patterns: Vec<AccessPattern> = build_access_patterns_checked(ssa)?;
    types::classify_aggregates_checked(&patterns)
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveredTypesError {
    #[error("{0}")]
    Memory(#[source] TypeRecoveryRefusal),
    #[error("{0}")]
    Gc(#[source] Error),
}

pub fn recover_types_full(
    bytes: &[u8],
    ssa: &SsaFunction,
) -> std::result::Result<RecoveredTypes, RecoveredTypesError> {
    let aggregates: Vec<(BaseOrigin, RecoveredType)> =
        recover_types(ssa).map_err(RecoveredTypesError::Memory)?;
    let gc_graph: GcTypeGraph = recover_gc_types(bytes).map_err(RecoveredTypesError::Gc)?;
    Ok(RecoveredTypes::new(aggregates, gc_graph))
}

fn build_access_patterns_checked(
    ssa: &SsaFunction,
) -> std::result::Result<Vec<AccessPattern>, TypeRecoveryRefusal> {
    let mut out: Vec<AccessPattern> = Vec::new();
    let mut resolver: AddressResolver<'_> = AddressResolver::new(ssa)?;
    for block in &ssa.blocks {
        for value_id in &block.instrs {
            let Some(definition): Option<&ValueDef> = ssa.values.get(value_id.0 as usize) else {
                return Err(TypeRecoveryRefusal::AmbiguousAddress);
            };
            if let ValueDef::Load {
                addr, memarg, kind, ..
            } = definition
            {
                let (base_origin, static_addend, index_stride): (BaseOrigin, u64, Option<u64>) =
                    resolver.resolve_address(*addr)?;
                if index_stride.is_some_and(|stride: u64| stride != u64::from(kind.width_bytes())) {
                    return Err(TypeRecoveryRefusal::InconsistentArray);
                }
                let offset_class: i32 = checked_declaration_offset(static_addend, memarg.offset)?;
                out.push(AccessPattern {
                    load_kind: Some(*kind),
                    store_kind: None,
                    width: kind.width_bytes(),
                    alignment: alignment_from_exponent(memarg.align),
                    offset_class,
                    base_origin,
                    is_indexed: index_stride.is_some(),
                });
            }
        }
        for store in &block.stores {
            let (base_origin, static_addend, index_stride): (BaseOrigin, u64, Option<u64>) =
                resolver.resolve_address(store.addr)?;
            if index_stride.is_some_and(|stride: u64| stride != u64::from(store.kind.width_bytes()))
            {
                return Err(TypeRecoveryRefusal::InconsistentArray);
            }
            let offset_class: i32 = checked_declaration_offset(static_addend, store.memarg.offset)?;
            out.push(AccessPattern {
                load_kind: None,
                store_kind: Some(store.kind),
                width: store.kind.width_bytes(),
                alignment: alignment_from_exponent(store.memarg.align),
                offset_class,
                base_origin,
                is_indexed: index_stride.is_some(),
            });
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
enum AddressTerm {
    Base {
        origin: BaseOrigin,
        addend: u64,
        index_stride: Option<u64>,
    },
    Absolute(u64),
    Index {
        stride: u64,
        addend: u64,
    },
}

#[derive(Debug, Clone, Copy)]
struct AddressResolution {
    term: AddressTerm,
    height: u32,
}

#[derive(Debug, Clone, Copy)]
enum AddressResolutionState {
    Unvisited,
    Visiting,
    Resolved(std::result::Result<AddressResolution, TypeRecoveryRefusal>),
}

#[derive(Debug, Clone, Copy)]
enum AddressDefinition {
    Param(u16),
    Global(u32),
    I32Const(i32),
    I64Const(i64),
    Binary(OpKind, ValueId, ValueId),
    Extend(ValueId),
    Unsupported,
}

struct AddressResolver<'a> {
    ssa: &'a SsaFunction,
    states: Vec<AddressResolutionState>,
    remaining_steps: usize,
}

impl<'a> AddressResolver<'a> {
    fn new(ssa: &'a SsaFunction) -> std::result::Result<Self, TypeRecoveryRefusal> {
        let dependency_count: usize = ssa
            .values
            .iter()
            .try_fold(0usize, |count: usize, definition: &ValueDef| {
                count.checked_add(address_dependency_count(definition))
            })
            .ok_or(TypeRecoveryRefusal::AddressBudget)?;
        let root_count: usize = ssa
            .blocks
            .iter()
            .try_fold(0usize, |count: usize, block: &SsaBlock| {
                count
                    .checked_add(block.instrs.len())
                    .and_then(|value: usize| value.checked_add(block.stores.len()))
            })
            .ok_or(TypeRecoveryRefusal::AddressBudget)?;
        let remaining_steps: usize = ssa
            .values
            .len()
            .checked_add(dependency_count)
            .and_then(|value: usize| value.checked_add(root_count))
            .ok_or(TypeRecoveryRefusal::AddressBudget)?;
        Ok(Self {
            ssa,
            states: vec![AddressResolutionState::Unvisited; ssa.values.len()],
            remaining_steps,
        })
    }

    fn resolve_address(
        &mut self,
        value_id: ValueId,
    ) -> std::result::Result<(BaseOrigin, u64, Option<u64>), TypeRecoveryRefusal> {
        match self.resolve_term(value_id, 0)?.term {
            AddressTerm::Base {
                origin,
                addend,
                index_stride,
            } => Ok((origin, addend, index_stride)),
            AddressTerm::Absolute(addend) => Ok((BaseOrigin::Heap, addend, None)),
            AddressTerm::Index { .. } => Err(TypeRecoveryRefusal::AmbiguousAddress),
        }
    }

    fn resolve_term(
        &mut self,
        value_id: ValueId,
        depth: u32,
    ) -> std::result::Result<AddressResolution, TypeRecoveryRefusal> {
        if depth >= MAX_ORIGIN_DEPTH {
            return Err(TypeRecoveryRefusal::AddressDepth);
        }
        self.remaining_steps = self
            .remaining_steps
            .checked_sub(1)
            .ok_or(TypeRecoveryRefusal::AddressBudget)?;
        let index: usize =
            usize::try_from(value_id.0).map_err(|_| TypeRecoveryRefusal::AmbiguousAddress)?;
        let state: AddressResolutionState = *self
            .states
            .get(index)
            .ok_or(TypeRecoveryRefusal::AmbiguousAddress)?;
        match state {
            AddressResolutionState::Visiting => return Err(TypeRecoveryRefusal::CyclicAddress),
            AddressResolutionState::Resolved(result) => {
                return validate_cached_resolution(result, depth);
            }
            AddressResolutionState::Unvisited => {}
        }
        self.states[index] = AddressResolutionState::Visiting;
        let definition: AddressDefinition = address_definition(
            self.ssa
                .values
                .get(index)
                .ok_or(TypeRecoveryRefusal::AmbiguousAddress)?,
        );
        let result: std::result::Result<AddressResolution, TypeRecoveryRefusal> =
            self.resolve_definition(definition, depth);
        self.states[index] = AddressResolutionState::Resolved(result);
        validate_cached_resolution(result, depth)
    }

    fn resolve_definition(
        &mut self,
        definition: AddressDefinition,
        depth: u32,
    ) -> std::result::Result<AddressResolution, TypeRecoveryRefusal> {
        match definition {
            AddressDefinition::Param(index) => Ok(AddressResolution {
                term: AddressTerm::Base {
                    origin: BaseOrigin::Param(u32::from(index)),
                    addend: 0,
                    index_stride: None,
                },
                height: 0,
            }),
            AddressDefinition::Global(global) => Ok(AddressResolution {
                term: AddressTerm::Base {
                    origin: BaseOrigin::Global(global),
                    addend: 0,
                    index_stride: None,
                },
                height: 0,
            }),
            AddressDefinition::I32Const(value) => Ok(AddressResolution {
                term: AddressTerm::Absolute(u64::from(u32::from_ne_bytes(value.to_ne_bytes()))),
                height: 0,
            }),
            AddressDefinition::I64Const(value) => Ok(AddressResolution {
                term: AddressTerm::Absolute(u64::from_ne_bytes(value.to_ne_bytes())),
                height: 0,
            }),
            AddressDefinition::Binary(OpKind::I32Add | OpKind::I64Add, left, right) => {
                let left: AddressResolution = self.resolve_term(left, depth + 1)?;
                let right: AddressResolution = self.resolve_term(right, depth + 1)?;
                Ok(AddressResolution {
                    term: combine_address_terms(left.term, right.term)?,
                    height: resolution_height(left.height, right.height)?,
                })
            }
            AddressDefinition::Binary(OpKind::I32Mul | OpKind::I64Mul, left, right) => {
                let left: AddressResolution = self.resolve_term(left, depth + 1)?;
                let right: AddressResolution = self.resolve_term(right, depth + 1)?;
                let (source, stride): (AddressTerm, u64) = match (left.term, right.term) {
                    (AddressTerm::Absolute(stride), source)
                    | (source, AddressTerm::Absolute(stride))
                        if !matches!(source, AddressTerm::Absolute(_)) =>
                    {
                        (source, stride)
                    }
                    _ => {
                        return Err(TypeRecoveryRefusal::AmbiguousAddress);
                    }
                };
                validate_index_source(source)?;
                if stride == 0 {
                    return Err(TypeRecoveryRefusal::InconsistentArray);
                }
                Ok(AddressResolution {
                    term: AddressTerm::Index { stride, addend: 0 },
                    height: resolution_height(left.height, right.height)?,
                })
            }
            AddressDefinition::Binary(OpKind::I32Shl | OpKind::I64Shl, source, shift) => {
                let source: AddressResolution = self.resolve_term(source, depth + 1)?;
                let shift_resolution: AddressResolution = self.resolve_term(shift, depth + 1)?;
                let AddressTerm::Absolute(shift): AddressTerm = shift_resolution.term else {
                    return Err(TypeRecoveryRefusal::AmbiguousAddress);
                };
                let shift: u32 =
                    u32::try_from(shift).map_err(|_| TypeRecoveryRefusal::InconsistentArray)?;
                let stride: u64 = 1u64
                    .checked_shl(shift)
                    .ok_or(TypeRecoveryRefusal::InconsistentArray)?;
                validate_index_source(source.term)?;
                Ok(AddressResolution {
                    term: AddressTerm::Index { stride, addend: 0 },
                    height: resolution_height(source.height, shift_resolution.height)?,
                })
            }
            AddressDefinition::Extend(value_id) => {
                let inner: AddressResolution = self.resolve_term(value_id, depth + 1)?;
                Ok(AddressResolution {
                    term: inner.term,
                    height: inner
                        .height
                        .checked_add(1)
                        .ok_or(TypeRecoveryRefusal::AddressDepth)?,
                })
            }
            AddressDefinition::Binary(_, _, _) | AddressDefinition::Unsupported => {
                Err(TypeRecoveryRefusal::AmbiguousAddress)
            }
        }
    }
}

fn address_definition(definition: &ValueDef) -> AddressDefinition {
    match definition {
        ValueDef::Param(_, index) => AddressDefinition::Param(*index),
        ValueDef::GlobalGet { global, .. } => AddressDefinition::Global(*global),
        ValueDef::Const(ConstVal::I32(value)) => AddressDefinition::I32Const(*value),
        ValueDef::Const(ConstVal::I64(value)) => AddressDefinition::I64Const(*value),
        ValueDef::Op { kind, args, .. } if args.len() == 2 => {
            AddressDefinition::Binary(*kind, args[0], args[1])
        }
        ValueDef::Unary {
            op: UnOp::I64ExtendI32U,
            arg,
            ..
        } => AddressDefinition::Extend(*arg),
        ValueDef::Const(_)
        | ValueDef::Phi { .. }
        | ValueDef::Op { .. }
        | ValueDef::Unary { .. }
        | ValueDef::Select { .. }
        | ValueDef::Load { .. }
        | ValueDef::Call { .. }
        | ValueDef::CallIndirect { .. }
        | ValueDef::MemorySize { .. }
        | ValueDef::MemoryGrow { .. } => AddressDefinition::Unsupported,
    }
}

fn address_dependency_count(definition: &ValueDef) -> usize {
    match address_definition(definition) {
        AddressDefinition::Binary(_, _, _) => 2,
        AddressDefinition::Extend(_) => 1,
        AddressDefinition::Param(_)
        | AddressDefinition::Global(_)
        | AddressDefinition::I32Const(_)
        | AddressDefinition::I64Const(_)
        | AddressDefinition::Unsupported => 0,
    }
}

fn validate_cached_resolution(
    result: std::result::Result<AddressResolution, TypeRecoveryRefusal>,
    depth: u32,
) -> std::result::Result<AddressResolution, TypeRecoveryRefusal> {
    let resolution: AddressResolution = result?;
    let deepest: u32 = depth
        .checked_add(resolution.height)
        .ok_or(TypeRecoveryRefusal::AddressDepth)?;
    if deepest >= MAX_ORIGIN_DEPTH {
        return Err(TypeRecoveryRefusal::AddressDepth);
    }
    Ok(resolution)
}

fn resolution_height(left: u32, right: u32) -> std::result::Result<u32, TypeRecoveryRefusal> {
    left.max(right)
        .checked_add(1)
        .ok_or(TypeRecoveryRefusal::AddressDepth)
}

const fn validate_index_source(term: AddressTerm) -> std::result::Result<(), TypeRecoveryRefusal> {
    match term {
        AddressTerm::Base {
            addend: 0,
            index_stride: None,
            ..
        } => Ok(()),
        AddressTerm::Base { .. } | AddressTerm::Absolute(_) | AddressTerm::Index { .. } => {
            Err(TypeRecoveryRefusal::AmbiguousAddress)
        }
    }
}

fn combine_address_terms(
    left: AddressTerm,
    right: AddressTerm,
) -> std::result::Result<AddressTerm, TypeRecoveryRefusal> {
    match (left, right) {
        (AddressTerm::Absolute(left), AddressTerm::Absolute(right)) => left
            .checked_add(right)
            .map(AddressTerm::Absolute)
            .ok_or(TypeRecoveryRefusal::OffsetOutOfRange),
        (
            AddressTerm::Base {
                origin,
                addend,
                index_stride,
            },
            AddressTerm::Absolute(extra),
        )
        | (
            AddressTerm::Absolute(extra),
            AddressTerm::Base {
                origin,
                addend,
                index_stride,
            },
        ) => Ok(AddressTerm::Base {
            origin,
            addend: addend
                .checked_add(extra)
                .ok_or(TypeRecoveryRefusal::OffsetOutOfRange)?,
            index_stride,
        }),
        (
            AddressTerm::Base {
                origin,
                addend,
                index_stride,
            },
            AddressTerm::Index {
                stride,
                addend: extra,
            },
        )
        | (
            AddressTerm::Index {
                stride,
                addend: extra,
            },
            AddressTerm::Base {
                origin,
                addend,
                index_stride,
            },
        ) => {
            if index_stride.is_some() {
                return Err(TypeRecoveryRefusal::AmbiguousAddress);
            }
            Ok(AddressTerm::Base {
                origin,
                addend: addend
                    .checked_add(extra)
                    .ok_or(TypeRecoveryRefusal::OffsetOutOfRange)?,
                index_stride: Some(stride),
            })
        }
        (AddressTerm::Index { stride, addend }, AddressTerm::Absolute(extra))
        | (AddressTerm::Absolute(extra), AddressTerm::Index { stride, addend }) => {
            Ok(AddressTerm::Index {
                stride,
                addend: addend
                    .checked_add(extra)
                    .ok_or(TypeRecoveryRefusal::OffsetOutOfRange)?,
            })
        }
        (AddressTerm::Index { .. }, AddressTerm::Index { .. })
        | (AddressTerm::Base { .. }, AddressTerm::Base { .. }) => {
            Err(TypeRecoveryRefusal::AmbiguousAddress)
        }
    }
}

fn checked_declaration_offset(
    address_addend: u64,
    memory_offset: u64,
) -> std::result::Result<i32, TypeRecoveryRefusal> {
    let offset: u64 = address_addend
        .checked_add(memory_offset)
        .ok_or(TypeRecoveryRefusal::OffsetOutOfRange)?;
    i32::try_from(offset).map_err(|_| TypeRecoveryRefusal::OffsetOutOfRange)
}

fn alignment_from_exponent(align: u8) -> u32 {
    1u32.checked_shl(u32::from(align))
        .map_or(u32::MAX, |value: u32| value)
}

const MAX_ORIGIN_DEPTH: u32 = 1024;

pub(crate) const MAX_RENDER_INDENT: usize = 64;

pub(crate) fn classify_base_origin(v: ValueId, ssa: &SsaFunction) -> BaseOrigin {
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
        assert!(matches!(recover_types(&ssa), Ok(recovered) if recovered.len() == 1));
    }
}
