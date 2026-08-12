#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::Arc;

use disrobe_ir::payload::{
    DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnFlow,
};
use disrobe_nir::{NirFunction, NirInstr, NirModule, NirOp, SourceLang, SourceRef};
use disrobe_query::{
    CallOutcome, FunctionId, Module, NavigationLimitError, NavigationLimits, NavigationQueryError,
    NeighborhoodDirection, NeighborhoodLimits,
};

fn insn(
    offset: u64,
    flow: InsnFlow,
    branch_target: Option<u64>,
    mnemonic: &str,
) -> DisasmInstruction {
    DisasmInstruction {
        offset,
        bytes: vec![0x90],
        mnemonic: mnemonic.to_owned(),
        operands: branch_target.map_or_else(Vec::new, |target: u64| vec![format!("0x{target:x}")]),
        flow,
        branch_target,
        ..DisasmInstruction::default()
    }
}

fn symbol(address: u64, name: &str, kind: DisasmSymbolKind) -> DisasmSymbol {
    DisasmSymbol {
        address,
        name: name.to_owned(),
        kind,
    }
}

fn navigation_module() -> Module {
    let payload: DisasmPayload = DisasmPayload {
        source_hash: [0x5au8; 32],
        instructions: vec![
            insn(0x10, InsnFlow::Call, Some(0x40), "call"),
            insn(0x11, InsnFlow::Call, Some(0x42), "call"),
            insn(0x12, InsnFlow::Call, Some(0x80), "call"),
            insn(0x13, InsnFlow::Call, Some(0x999), "call"),
            insn(0x14, InsnFlow::IndirectCall, None, "call"),
            insn(0x15, InsnFlow::Return, None, "ret"),
            insn(0x40, InsnFlow::Call, Some(0x60), "call"),
            insn(0x41, InsnFlow::Return, None, "ret"),
            insn(0x42, InsnFlow::Sequential, None, "nop"),
            insn(0x60, InsnFlow::Call, Some(0x40), "call"),
            insn(0x61, InsnFlow::Call, Some(0x60), "call"),
            insn(0x62, InsnFlow::Return, None, "ret"),
        ],
        symbol_table: vec![
            symbol(0x10, "caller", DisasmSymbolKind::Export),
            symbol(0x40, "duplicate", DisasmSymbolKind::Function),
            symbol(0x60, "duplicate", DisasmSymbolKind::Function),
            symbol(0x80, "send", DisasmSymbolKind::Import),
        ],
    };
    Module::from_disasm(&payload)
}

fn repeated_self_call_module(name_bytes: usize, call_count: usize) -> Module {
    let instructions: Vec<DisasmInstruction> = (0..call_count)
        .map(|index: usize| {
            insn(
                0x100u64.saturating_add(u64::try_from(index).unwrap_or_default()),
                InsnFlow::Call,
                Some(0x100),
                "call",
            )
        })
        .collect();
    Module::from_disasm(&DisasmPayload {
        source_hash: [0x91u8; 32],
        instructions,
        symbol_table: vec![symbol(
            0x100,
            &"n".repeat(name_bytes),
            DisasmSymbolKind::Function,
        )],
    })
}

const fn navigation_limits() -> NavigationLimits {
    NavigationLimits {
        functions: 1_024,
        instructions: 16_384,
        calls: 16_384,
        candidate_records: 32_768,
        retained_bytes: 16 * 1024 * 1024,
    }
}

#[test]
fn navigation_rejects_retained_bytes_before_large_names_are_materialized() {
    const RETAINED_LIMIT: usize = 32 * 1024;
    let module: Module = repeated_self_call_module(64 * 1024, 64);
    let error: NavigationLimitError = module
        .navigation_analysis(NavigationLimits {
            functions: 1,
            instructions: 64,
            calls: 64,
            candidate_records: 64,
            retained_bytes: RETAINED_LIMIT,
        })
        .expect_err("large retained names must be refused before analysis allocation");
    assert!(matches!(
        error,
        NavigationLimitError::RetainedBytes {
            limit: RETAINED_LIMIT
        }
    ));
}

#[test]
fn repeated_calls_share_caller_names_and_classified_outcomes() {
    let module: Module = repeated_self_call_module(16 * 1024, 64);
    let analysis: disrobe_query::NavigationAnalysis = module
        .navigation_analysis(NavigationLimits {
            functions: 1,
            instructions: 64,
            calls: 64,
            candidate_records: 64,
            retained_bytes: 128 * 1024,
        })
        .expect("shared analysis fits retained-byte ceiling");
    assert_eq!(analysis.calls().len(), 64);
    assert!(Arc::ptr_eq(
        &analysis.calls()[0].caller_name,
        &analysis.calls()[63].caller_name
    ));
    assert!(Arc::ptr_eq(
        &analysis.calls()[0].outcome,
        &analysis.calls()[63].outcome
    ));
}

#[test]
fn function_ids_bind_source_content_and_address_not_name_or_index() {
    let module: Module = navigation_module();
    let duplicates: Vec<&disrobe_query::Function> = module
        .functions()
        .iter()
        .filter(|function: &&disrobe_query::Function| function.name == "duplicate")
        .collect();
    assert_eq!(duplicates.len(), 2);

    let first: FunctionId = module.function_id(duplicates[0]);
    let second: FunctionId = module.function_id(duplicates[1]);
    assert_ne!(first, second);
    assert_eq!(first.address(), 0x40);
    assert_eq!(second.address(), 0x60);

    let encoded: String = second.to_string();
    let parsed: FunctionId = encoded.parse().expect("parse stable function id");
    assert_eq!(parsed, second);
    assert_eq!(
        module.function_by_id(&parsed).expect("resolve id").address,
        0x60
    );

    let foreign: FunctionId = FunctionId::new([0x33u8; 32], 0x60);
    let error: disrobe_query::FunctionLookupError = module
        .function_by_id(&foreign)
        .expect_err("foreign source hash must be rejected");
    assert!(matches!(
        error,
        disrobe_query::FunctionLookupError::SourceMismatch { .. }
    ));
}

#[test]
fn navigation_calls_report_every_direct_and_indirect_outcome() {
    let module: Module = navigation_module();
    let calls: Vec<disrobe_query::NavigationCall> = module
        .navigation_calls(navigation_limits())
        .expect("bounded navigation calls");
    assert_eq!(calls.len(), 8);
    assert!(matches!(
        calls[0].outcome.as_ref(),
        CallOutcome::FunctionStart { address: 0x40, .. }
    ));
    assert!(matches!(
        calls[1].outcome.as_ref(),
        CallOutcome::FunctionInterior {
            function_address: 0x40,
            target_address: 0x42,
            ..
        }
    ));
    assert!(matches!(
        calls[2].outcome.as_ref(),
        CallOutcome::Symbol { address: 0x80, .. }
    ));
    assert!(matches!(
        calls[3].outcome.as_ref(),
        CallOutcome::Unresolved { address: 0x999 }
    ));
    assert!(matches!(calls[4].outcome.as_ref(), CallOutcome::Indirect));
    assert!(calls.windows(2).all(
        |window: &[disrobe_query::NavigationCall]| window[0].call_site <= window[1].call_site
    ));
}

#[test]
fn exact_start_inside_an_overlapping_function_remains_ambiguous() {
    let source: SourceRef = SourceRef::new(SourceLang::NativeX86, 0x10);
    let module: Module = Module::from_nir(&NirModule {
        source_hash: [0x39u8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![
            NirFunction {
                name: "caller".to_owned(),
                address: 0x10,
                end: 0x20,
                is_export: false,
                instructions: vec![NirInstr {
                    address: 0x10,
                    op: NirOp::Call { target: Some(0x50) },
                    source: source.clone(),
                    ..NirInstr::default()
                }],
                source: source.clone(),
            },
            NirFunction {
                name: "outer".to_owned(),
                address: 0x40,
                end: 0x80,
                is_export: false,
                instructions: Vec::new(),
                source: source.clone(),
            },
            NirFunction {
                name: "inner".to_owned(),
                address: 0x50,
                end: 0x60,
                is_export: false,
                instructions: Vec::new(),
                source,
            },
        ],
        symbols: Vec::new(),
    });
    let calls: Vec<disrobe_query::NavigationCall> = module
        .navigation_calls(navigation_limits())
        .expect("bounded overlap classification");
    assert!(matches!(
        calls.as_slice(),
        [disrobe_query::NavigationCall {
            outcome,
            ..
        }] if matches!(
            outcome.as_ref(),
            CallOutcome::AmbiguousFunction { candidates, .. } if candidates.len() == 2
        )
    ));
}

#[test]
fn same_address_function_ids_round_trip_to_each_distinct_function() {
    let source: SourceRef = SourceRef::new(SourceLang::NativeX86, 0x40);
    let module: Module = Module::from_nir(&NirModule {
        source_hash: [0x3au8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![
            NirFunction {
                name: "first".to_owned(),
                address: 0x40,
                end: 0x40,
                is_export: false,
                instructions: Vec::new(),
                source: source.clone(),
            },
            NirFunction {
                name: "second".to_owned(),
                address: 0x40,
                end: 0x41,
                is_export: false,
                instructions: Vec::new(),
                source,
            },
        ],
        symbols: Vec::new(),
    });
    let summaries: Vec<disrobe_query::FunctionSummary> = module
        .function_summaries(navigation_limits())
        .expect("bounded same-address summaries");
    assert_eq!(summaries.len(), 2);
    assert_ne!(summaries[0].id, summaries[1].id);
    for (summary, expected_name) in summaries.iter().zip(["first", "second"]) {
        let encoded: String = summary.id.to_string();
        assert_eq!(encoded.len(), FunctionId::MAX_ENCODED_LEN);
        let parsed: FunctionId = encoded.parse().expect("parse returned id");
        assert_eq!(
            module
                .function_by_id(&parsed)
                .expect("resolve returned id")
                .name,
            expected_name
        );
    }
}

#[test]
fn same_address_function_ids_are_stable_when_records_are_reordered() {
    let source: SourceRef = SourceRef::new(SourceLang::NativeX86, 0x40);
    let first: NirFunction = NirFunction {
        name: "first".to_owned(),
        address: 0x40,
        end: 0x40,
        is_export: false,
        instructions: Vec::new(),
        source: source.clone(),
    };
    let second: NirFunction = NirFunction {
        name: "second".to_owned(),
        address: 0x40,
        end: 0x41,
        is_export: false,
        instructions: Vec::new(),
        source,
    };
    let source_hash: [u8; 32] = [0x3bu8; 32];
    let ordered: Module = Module::from_nir(&NirModule {
        source_hash,
        lang: SourceLang::NativeX86,
        functions: vec![first.clone(), second.clone()],
        symbols: Vec::new(),
    });
    let reordered: Module = Module::from_nir(&NirModule {
        source_hash,
        lang: SourceLang::NativeX86,
        functions: vec![second, first],
        symbols: Vec::new(),
    });
    let ids_by_name: BTreeMap<&str, FunctionId> = ordered
        .functions()
        .iter()
        .map(|function: &disrobe_query::Function| {
            (function.name.as_str(), ordered.function_id(function))
        })
        .collect();
    for function in reordered.functions() {
        let expected: &FunctionId = ids_by_name
            .get(function.name.as_str())
            .expect("ordered function id");
        assert_eq!(&reordered.function_id(function), expected);
    }
}

#[test]
fn identical_same_address_function_records_have_one_canonical_identity() {
    let source: SourceRef = SourceRef::new(SourceLang::NativeX86, 0x40);
    let duplicate: NirFunction = NirFunction {
        name: "duplicate".to_owned(),
        address: 0x40,
        end: 0x41,
        is_export: false,
        instructions: Vec::new(),
        source,
    };
    let module: Module = Module::from_nir(&NirModule {
        source_hash: [0x3cu8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![duplicate.clone(), duplicate],
        symbols: Vec::new(),
    });
    assert_eq!(module.functions().len(), 1);
    let summaries: Vec<disrobe_query::FunctionSummary> = module
        .function_summaries(navigation_limits())
        .expect("bounded canonical summary");
    assert_eq!(summaries.len(), 1);
    assert_eq!(
        module
            .function_by_id(&summaries[0].id)
            .expect("canonical function id")
            .name,
        "duplicate"
    );
}

#[test]
fn summary_and_xrefs_resolve_duplicate_names_by_stable_id() {
    let module: Module = navigation_module();
    let target: &disrobe_query::Function = module
        .functions()
        .iter()
        .find(|function: &&disrobe_query::Function| function.address == 0x60)
        .expect("second duplicate");
    let id: FunctionId = module.function_id(target);

    let summary: disrobe_query::FunctionSummary = module
        .function_summary(&id, navigation_limits())
        .expect("function summary");
    assert_eq!(summary.id, id);
    assert_eq!(summary.outgoing_calls, 2);
    assert_eq!(summary.incoming_calls, 2);
    assert_eq!(summary.indirect_calls, 0);

    let xrefs: Vec<disrobe_query::XrefMatch> = module
        .bounded_xrefs_to_function(&id, 64)
        .expect("bounded xrefs by id");
    let offsets: Vec<u64> = xrefs
        .iter()
        .map(|xref: &disrobe_query::XrefMatch| xref.from_offset)
        .collect();
    assert_eq!(offsets, vec![0x40, 0x61]);
    assert!(
        xrefs
            .iter()
            .all(|xref: &disrobe_query::XrefMatch| xref.to_address == 0x60)
    );
    let encoded: serde_json::Value = serde_json::to_value(&xrefs[0]).expect("serialize xref");
    assert_eq!(
        encoded.as_object().map(serde_json::Map::len),
        Some(5),
        "existing XrefMatch serialization must not gain an MCP-only address field"
    );
    assert!(encoded.get("from_function_address").is_none());
}

#[test]
fn navigation_xrefs_share_caller_names_and_enforce_retained_bytes() {
    let module: Module = repeated_self_call_module(64 * 1024, 64);
    let target: &disrobe_query::Function = &module.functions()[0];
    let id: FunctionId = module.function_id(target);
    let error: NavigationQueryError = module
        .bounded_navigation_xrefs_to_function(&id, 64, 32 * 1024)
        .expect_err("xref caller name exceeds retained-byte ceiling");
    assert!(matches!(
        error,
        NavigationQueryError::Limit(NavigationLimitError::RetainedBytes { limit: 32_768 })
    ));

    let xrefs: Vec<disrobe_query::NavigationXref> = module
        .bounded_navigation_xrefs_to_function(&id, 64, 128 * 1024)
        .expect("shared xrefs fit retained-byte ceiling");
    assert_eq!(xrefs.len(), 64);
    assert!(Arc::ptr_eq(
        &xrefs[0].from_function_name,
        &xrefs[63].from_function_name
    ));
}

#[test]
fn neighborhood_is_cycle_safe_deterministic_and_depth_bounded() {
    let module: Module = navigation_module();
    let entry: &disrobe_query::Function = module
        .functions()
        .iter()
        .find(|function: &&disrobe_query::Function| function.address == 0x40)
        .expect("entry");
    let entry_id: FunctionId = module.function_id(entry);
    let limits: NeighborhoodLimits = NeighborhoodLimits {
        max_nodes: 64,
        max_calls: 128,
        analysis: NavigationLimits {
            functions: 64,
            instructions: 128,
            calls: 128,
            candidate_records: 128,
            retained_bytes: 1024 * 1024,
        },
    };

    let first: disrobe_query::Neighborhood = module
        .neighborhood(&[entry_id], 8, NeighborhoodDirection::Both, limits)
        .expect("cycle-safe neighborhood");
    let second: disrobe_query::Neighborhood = module
        .neighborhood(&[entry_id], 8, NeighborhoodDirection::Both, limits)
        .expect("repeat neighborhood");

    assert_eq!(first, second);
    assert!(!first.truncated);
    assert_eq!(first.nodes.len(), 3);
    assert_eq!(
        first
            .nodes
            .iter()
            .filter(|node: &&disrobe_query::NeighborhoodNode| node.function.id == entry_id)
            .count(),
        1
    );
    assert!(
        first
            .nodes
            .iter()
            .all(|node: &disrobe_query::NeighborhoodNode| node.depth <= 8)
    );
    assert!(
        first
            .calls
            .iter()
            .any(|call: &disrobe_query::NavigationCall| {
                call.caller_id.address() == 0x60
                    && matches!(
                        call.outcome.as_ref(),
                        CallOutcome::FunctionStart { address: 0x60, .. }
                    )
            })
    );
}

#[test]
fn neighborhood_rejects_entry_sets_above_the_node_limit_before_analysis() {
    let module: Module = navigation_module();
    let entries: Vec<FunctionId> = module
        .functions()
        .iter()
        .take(2)
        .map(|function: &disrobe_query::Function| module.function_id(function))
        .collect();
    let error: NavigationQueryError = module
        .neighborhood(
            &entries,
            1,
            NeighborhoodDirection::Both,
            NeighborhoodLimits {
                max_nodes: 1,
                max_calls: 8,
                analysis: NavigationLimits {
                    functions: 8,
                    instructions: 16,
                    calls: 8,
                    candidate_records: 8,
                    retained_bytes: 64 * 1024,
                },
            },
        )
        .expect_err("two distinct entries exceed max_nodes one");
    assert!(matches!(
        error,
        NavigationQueryError::Limit(NavigationLimitError::NeighborhoodNodes {
            actual: 2,
            limit: 1
        })
    ));
}

#[test]
fn neighborhood_rejects_working_set_growth_before_building_adjacency_indexes() {
    let module: Module = repeated_self_call_module(32, 128);
    let analysis: disrobe_query::NavigationAnalysis = module
        .navigation_analysis(navigation_limits())
        .expect("analysis fits its construction ceiling");
    let entry: FunctionId = module.function_id(&module.functions()[0]);
    let retained_limit: usize = analysis.working_set_bytes();
    let error: NavigationQueryError = module
        .neighborhood_from_analysis(
            &analysis,
            &[entry],
            1,
            NeighborhoodDirection::Both,
            NeighborhoodLimits {
                max_nodes: 1,
                max_calls: 128,
                analysis: NavigationLimits {
                    retained_bytes: retained_limit,
                    ..navigation_limits()
                },
            },
        )
        .expect_err("adjacency indexes must be charged beyond the analysis working set");
    assert!(matches!(
        error,
        NavigationQueryError::Limit(NavigationLimitError::RetainedBytes { limit })
            if limit == retained_limit
    ));
}

#[test]
fn zero_function_module_has_empty_navigation_results() {
    let module: Module = Module::from_disasm(&DisasmPayload {
        source_hash: [0x11u8; 32],
        instructions: Vec::new(),
        symbol_table: Vec::new(),
    });
    assert!(
        module
            .navigation_calls(navigation_limits())
            .expect("bounded empty calls")
            .is_empty()
    );
    assert!(
        module
            .function_summaries(navigation_limits())
            .expect("bounded empty summaries")
            .is_empty()
    );
}

#[test]
fn legacy_call_graph_does_not_require_navigation_summary_construction() {
    let module: Module = repeated_self_call_module(20 * 1024 * 1024, 2);
    let graph: disrobe_query::CallGraph = module.call_graph();
    assert_eq!(graph.nodes.len(), 1);
    assert_eq!(graph.edges.len(), 2);
    assert_eq!(graph.edges[0].caller.len(), 20 * 1024 * 1024);
}

#[test]
fn nir_navigation_preserves_direct_indirect_and_stable_id_semantics() {
    let source_hash: [u8; 32] = [0x77u8; 32];
    let source: SourceRef = SourceRef::new(SourceLang::NativeX86, 0x10);
    let module: Module = Module::from_nir(&NirModule {
        source_hash,
        lang: SourceLang::NativeX86,
        functions: vec![
            NirFunction {
                name: "调用者🙂".to_owned(),
                address: 0x10,
                end: 0x20,
                is_export: true,
                instructions: vec![
                    NirInstr {
                        address: 0x10,
                        op: NirOp::Call { target: Some(0x40) },
                        mnemonic: "call".to_owned(),
                        operands: vec!["0x40".to_owned()],
                        source: source.clone(),
                        ..NirInstr::default()
                    },
                    NirInstr {
                        address: 0x11,
                        op: NirOp::IndirectCall,
                        mnemonic: "call".to_owned(),
                        operands: vec!["rax".to_owned()],
                        source: source.clone(),
                        ..NirInstr::default()
                    },
                ],
                source: source.clone(),
            },
            NirFunction {
                name: "目标".to_owned(),
                address: 0x40,
                end: 0x41,
                is_export: false,
                instructions: vec![NirInstr {
                    address: 0x40,
                    op: NirOp::Return,
                    mnemonic: "ret".to_owned(),
                    source: source.clone(),
                    ..NirInstr::default()
                }],
                source,
            },
        ],
        symbols: Vec::new(),
    });

    let calls: Vec<disrobe_query::NavigationCall> = module
        .navigation_calls(navigation_limits())
        .expect("bounded NIR navigation calls");
    assert_eq!(calls.len(), 2);
    assert!(matches!(
        calls[0].outcome.as_ref(),
        CallOutcome::FunctionStart { .. }
    ));
    assert!(matches!(calls[1].outcome.as_ref(), CallOutcome::Indirect));
    let target: &disrobe_query::Function = module
        .functions()
        .iter()
        .find(|function: &&disrobe_query::Function| function.address == 0x40)
        .expect("nir target");
    assert_eq!(
        module.function_id(target),
        FunctionId::new(source_hash, 0x40)
    );
}

#[test]
fn dense_overlapping_call_graph_stops_at_the_candidate_work_ceiling() {
    let source_hash: [u8; 32] = [0x88u8; 32];
    let functions: Vec<NirFunction> = (0u64..64)
        .map(|index: u64| NirFunction {
            name: format!("overlap_{index}"),
            address: index,
            end: 0x2_000,
            is_export: false,
            instructions: vec![NirInstr {
                address: index,
                op: NirOp::Call {
                    target: Some(0x1_000),
                },
                mnemonic: "call".to_owned(),
                operands: vec!["0x1000".to_owned()],
                source: SourceRef::new(SourceLang::NativeX86, index),
                ..NirInstr::default()
            }],
            source: SourceRef::new(SourceLang::NativeX86, index),
        })
        .collect();
    let module: Module = Module::from_nir(&NirModule {
        source_hash,
        lang: SourceLang::NativeX86,
        functions,
        symbols: Vec::new(),
    });
    let indexed: disrobe_query::NavigationAnalysis = module
        .navigation_analysis(NavigationLimits {
            functions: 64,
            instructions: 64,
            calls: 64,
            candidate_records: 64,
            retained_bytes: usize::MAX,
        })
        .expect("one target classification must not multiply work by call count");
    assert_eq!(indexed.calls().len(), 64);
    assert!(Arc::ptr_eq(
        &indexed.calls()[0].outcome,
        &indexed.calls()[63].outcome
    ));
    let error: NavigationLimitError = module
        .navigation_analysis(NavigationLimits {
            functions: 64,
            instructions: 64,
            calls: 64,
            candidate_records: 32,
            retained_bytes: usize::MAX,
        })
        .expect_err("64 overlapping callees across 64 calls exceed retained candidate work");
    assert!(matches!(
        error,
        NavigationLimitError::CandidateRecords { limit: 32 }
    ));
}
