#![allow(clippy::expect_used)]

use disrobe_nir::{
    NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_taint::{
    CALL_EDGE_TARGET_CAP, CallEdge, CallEdgeBuildError, CallEdgeEvidence, CallEdgeLabel,
    TaintConfig, TaintReport, analyze_with_call_edges,
};

const DISPATCH_ADDRESS: u64 = 0x100;
const READER_ADDRESS: u64 = 0x200;
const SINK_ADDRESS: u64 = 0x300;
const ALTERNATE_ADDRESS: u64 = 0x400;
const INDIRECT_SITE: u64 = 0x108;

fn instruction(address: u64, op: NirOp, mnemonic: &str) -> NirInstr {
    NirInstr {
        address,
        op,
        mnemonic: mnemonic.to_owned(),
        operands: Vec::new(),
        reads_memory: false,
        writes_memory: false,
        byte_width: false,
        source: SourceRef::new(SourceLang::NativeX86, address),
    }
}

fn function(name: &str, address: u64, instructions: Vec<NirInstr>) -> NirFunction {
    NirFunction {
        name: name.to_owned(),
        address,
        end: address + 0x40,
        is_export: address == DISPATCH_ADDRESS,
        instructions,
        source: SourceRef::new(SourceLang::NativeX86, address),
    }
}

fn module() -> NirModule {
    NirModule {
        source_hash: [0x21; 32],
        lang: SourceLang::NativeX86,
        functions: vec![
            function(
                "dispatch",
                DISPATCH_ADDRESS,
                vec![
                    instruction(INDIRECT_SITE, NirOp::IndirectCall, "call"),
                    instruction(
                        0x110,
                        NirOp::Call {
                            target: Some(SINK_ADDRESS),
                        },
                        "call",
                    ),
                    instruction(0x118, NirOp::Return, "ret"),
                ],
            ),
            function(
                "read_input",
                READER_ADDRESS,
                vec![
                    instruction(
                        READER_ADDRESS,
                        NirOp::ExternCall {
                            symbol: "recv".to_owned(),
                        },
                        "call",
                    ),
                    instruction(0x208, NirOp::Return, "ret"),
                ],
            ),
            function(
                "run_command",
                SINK_ADDRESS,
                vec![
                    instruction(
                        SINK_ADDRESS,
                        NirOp::ExternCall {
                            symbol: "system".to_owned(),
                        },
                        "call",
                    ),
                    instruction(0x308, NirOp::Return, "ret"),
                ],
            ),
            function(
                "alternate",
                ALTERNATE_ADDRESS,
                vec![instruction(0x408, NirOp::Return, "ret")],
            ),
        ],
        symbols: vec![
            NirSymbol {
                address: READER_ADDRESS,
                name: "read_input".to_owned(),
                kind: SymbolKind::Function,
            },
            NirSymbol {
                address: SINK_ADDRESS,
                name: "run_command".to_owned(),
                kind: SymbolKind::Function,
            },
            NirSymbol {
                address: ALTERNATE_ADDRESS,
                name: "alternate".to_owned(),
                kind: SymbolKind::Function,
            },
        ],
    }
}

fn finite_edge(targets: impl IntoIterator<Item = u64>) -> CallEdge {
    CallEdge::finite_set(
        INDIRECT_SITE,
        targets,
        CallEdgeEvidence::NavigationAmbiguousFunction,
    )
    .expect("test candidates are non-empty")
}

fn analyze(edges: &[CallEdge]) -> TaintReport {
    analyze_with_call_edges(
        &module(),
        &TaintConfig::from_lists(["recv"], ["system"]),
        edges,
    )
}

#[test]
fn finite_targets_drive_taint_and_are_serialized_with_the_finding() {
    let edge: CallEdge = finite_edge([READER_ADDRESS, ALTERNATE_ADDRESS]);
    let report: TaintReport = analyze(core::slice::from_ref(&edge));

    assert!(report.flow_in("dispatch", "read_input", "run_command"));
    assert!(!report.has_unresolved_calls());
    assert!(report.call_edges().contains(&edge));
    assert!(
        report.findings()[0]
            .path
            .iter()
            .any(|step| step.address == INDIRECT_SITE && step.kind == "call-finite-set")
    );
    let json: serde_json::Value = serde_json::to_value(&report).expect("serialize taint report");
    assert!(json["call_edges"].as_array().is_some_and(|edges| {
        edges.iter().any(|serialized| {
            serialized["site"] == INDIRECT_SITE
                && serialized["label"]["kind"] == "finite-set"
                && serialized["label"]["targets"]
                    == serde_json::json!([READER_ADDRESS, ALTERNATE_ADDRESS])
        })
    }));
}

#[test]
fn an_empty_finite_set_is_rejected_at_ingress() {
    let result: Result<CallEdge, CallEdgeBuildError> = CallEdge::finite_set(
        INDIRECT_SITE,
        [],
        CallEdgeEvidence::NavigationAmbiguousFunction,
    );
    assert_eq!(result, Err(CallEdgeBuildError::EmptyFiniteSet));
}

#[test]
fn exceeding_the_candidate_cap_is_symbolic_with_cap_evidence() {
    let edge: CallEdge = finite_edge(0..=CALL_EDGE_TARGET_CAP as u64);

    assert_eq!(edge.label, CallEdgeLabel::Symbolic);
    assert!(
        edge.evidence()
            .contains(&CallEdgeEvidence::CandidateSetLimit {
                observed_candidate_count: CALL_EDGE_TARGET_CAP + 1,
                limit: CALL_EDGE_TARGET_CAP,
            })
    );
}

#[test]
fn unresolved_and_symbolic_edges_remain_distinct_in_the_report() {
    let edges: [CallEdge; 2] = [
        CallEdge::symbolic(0x120, CallEdgeEvidence::NavigationIndirect),
        CallEdge::unresolved(INDIRECT_SITE, CallEdgeEvidence::NavigationIndirect),
    ];
    let report: TaintReport = analyze(&edges);

    assert!(report.call_edges().contains(&edges[0]));
    assert!(report.call_edges().contains(&edges[1]));
}

#[test]
fn duplicate_same_site_evidence_is_order_independent() {
    let first: CallEdge = CallEdge::definite(
        INDIRECT_SITE,
        READER_ADDRESS,
        CallEdgeEvidence::NavigationFunctionStart,
    );
    let second: CallEdge = finite_edge([ALTERNATE_ADDRESS, READER_ADDRESS]);

    let forward: TaintReport = analyze(&[first.clone(), second.clone()]);
    let reverse: TaintReport = analyze(&[second, first]);

    assert_eq!(forward, reverse);
    let same_site: Vec<&CallEdge> = forward
        .call_edges()
        .iter()
        .filter(|edge: &&CallEdge| edge.site == INDIRECT_SITE)
        .collect();
    assert_eq!(same_site.len(), 1);
    assert!(matches!(
        &same_site[0].label,
        CallEdgeLabel::FiniteSet { targets }
            if targets.as_slice() == [READER_ADDRESS, ALTERNATE_ADDRESS]
    ));
    assert_eq!(same_site[0].evidence().len(), 2);
    assert!(
        same_site[0]
            .evidence()
            .contains(&CallEdgeEvidence::NavigationFunctionStart)
    );
    assert!(
        same_site[0]
            .evidence()
            .contains(&CallEdgeEvidence::NavigationAmbiguousFunction)
    );
}

#[test]
fn a_finite_set_on_a_direct_call_keeps_non_internal_uncertainty() {
    let mut direct_module: NirModule = module();
    direct_module.functions[0].instructions[0].op = NirOp::Call {
        target: Some(READER_ADDRESS),
    };
    let edge: CallEdge = finite_edge([READER_ADDRESS, 0x9_999]);
    let report: TaintReport = analyze_with_call_edges(
        &direct_module,
        &TaintConfig::from_lists(["recv"], ["system"]),
        core::slice::from_ref(&edge),
    );

    assert!(report.flow_in("dispatch", "read_input", "run_command"));
    assert!(report.has_unresolved_calls());
    assert!(report.call_edges().iter().any(|candidate| {
        candidate.site == INDIRECT_SITE
            && matches!(
                &candidate.label,
                CallEdgeLabel::FiniteSet { targets }
                    if targets.as_slice() == [READER_ADDRESS, 0x9_999]
            )
    }));
    assert!(report.call_edges().iter().any(|candidate| {
        candidate.site == INDIRECT_SITE && candidate.label == CallEdgeLabel::Unresolved
    }));
    assert!(
        report.findings()[0]
            .path
            .iter()
            .any(|step| step.address == INDIRECT_SITE && step.kind == "call-unresolved")
    );
}
