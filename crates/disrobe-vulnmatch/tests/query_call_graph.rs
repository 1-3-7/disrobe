use std::collections::BTreeSet;

use disrobe_query::model::{CallGraph, CallGraphEdge, CallGraphNode};
use disrobe_vulnmatch::{
    AbstractArgument, Budget, CallGraphView, EdgeKind, FindingTier, FunctionId, QueryCallGraphView,
    ReachabilityEvidence, Rule, RuleStore, RuleStoreError, Severity, SinkSignature, TaintOracle,
    TaintStatus, analyze,
};

#[derive(Debug, Default)]
struct UnknownTaint;

impl TaintOracle for UnknownTaint {
    fn taint_status(
        &self,
        _source: &disrobe_vulnmatch::SourceClass,
        _site: &disrobe_vulnmatch::DirectCall,
    ) -> TaintStatus {
        TaintStatus::Unknown
    }
}

fn function_id(name: &str, address: u64) -> FunctionId {
    FunctionId::new(format!("query:{address:016x}:{name}"))
}

fn sink_rules() -> Result<RuleStore, RuleStoreError> {
    RuleStore::from_rules(vec![Rule {
        id: String::from("query-danger-sink"),
        cwe: String::from("CWE-999"),
        severity: Severity::High,
        sink: SinkSignature::ResolvedSymbol {
            canonical_name: String::from("danger_sink"),
            aliases: BTreeSet::new(),
        },
        requires_source: None,
        arg_constraints: Vec::new(),
    }])
}

#[test]
fn query_call_graph_direct_edges_prove_a_reachable_sink() {
    let graph: CallGraph = CallGraph {
        nodes: vec![
            CallGraphNode {
                name: String::from("main"),
                address: 0x100,
                is_export: true,
            },
            CallGraphNode {
                name: String::from("worker"),
                address: 0x200,
                is_export: false,
            },
            CallGraphNode {
                name: String::from("danger_sink"),
                address: 0x300,
                is_export: false,
            },
        ],
        edges: vec![
            CallGraphEdge {
                caller: String::from("main"),
                caller_address: 0x100,
                call_site: 0x110,
                callee: String::from("worker"),
                callee_address: 0x200,
            },
            CallGraphEdge {
                caller: String::from("worker"),
                caller_address: 0x200,
                call_site: 0x210,
                callee: String::from("danger_sink"),
                callee_address: 0x300,
            },
        ],
    };
    let view: QueryCallGraphView<'_> = QueryCallGraphView::new(&graph);
    let functions: Vec<FunctionId> = view.functions();
    let calls: Vec<disrobe_vulnmatch::DirectCall> = view.direct_calls();
    let edges: Vec<disrobe_vulnmatch::CallGraphEdge> = view.call_edges();
    let entries: Vec<FunctionId> = view.entry_points();

    assert_eq!(
        functions,
        vec![
            function_id("main", 0x100),
            function_id("worker", 0x200),
            function_id("danger_sink", 0x300),
        ]
    );
    assert_eq!(entries, vec![function_id("main", 0x100)]);
    assert!(!view.entry_points_complete());
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].arguments, Vec::<AbstractArgument>::new());
    assert_eq!(
        edges[0].kind,
        EdgeKind::Direct {
            callee: Some(function_id("worker", 0x200)),
        }
    );
    assert_eq!(
        edges[1].kind,
        EdgeKind::Direct {
            callee: Some(function_id("danger_sink", 0x300)),
        }
    );

    let rules_result: Result<RuleStore, RuleStoreError> = sink_rules();
    assert!(rules_result.is_ok(), "query sink rule must be valid");
    let Ok(rules) = rules_result else {
        return;
    };
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(128, 16);
    let report: disrobe_vulnmatch::Report = analyze(&view, &taint, &rules, &mut budget);
    let finding: Option<&disrobe_vulnmatch::Finding> = report.findings.first();

    assert!(finding.is_some(), "known sink must produce one finding");
    let Some(finding) = finding else {
        return;
    };
    assert_eq!(finding.tier, FindingTier::Reachable);
    assert_eq!(
        finding.evidence.reachability,
        ReachabilityEvidence::Reachable {
            distance: 1,
            weakest_edge_soundness: disrobe_vulnmatch::EdgeSoundness::High,
        }
    );
    assert!(
        finding.witness_path.is_some(),
        "reachable sink must retain a witness"
    );
    assert!(!report.complete);
}

#[test]
fn query_call_graph_unknown_target_preserves_reachability_unknown() {
    let graph: CallGraph = CallGraph {
        nodes: vec![
            CallGraphNode {
                name: String::from("main"),
                address: 0x100,
                is_export: true,
            },
            CallGraphNode {
                name: String::from("worker"),
                address: 0x200,
                is_export: false,
            },
            CallGraphNode {
                name: String::from("danger_sink"),
                address: 0x300,
                is_export: false,
            },
        ],
        edges: vec![
            CallGraphEdge {
                caller: String::from("main"),
                caller_address: 0x100,
                call_site: 0x110,
                callee: String::from("sub_180"),
                callee_address: 0x180,
            },
            CallGraphEdge {
                caller: String::from("worker"),
                caller_address: 0x200,
                call_site: 0x210,
                callee: String::from("danger_sink"),
                callee_address: 0x300,
            },
        ],
    };
    let view: QueryCallGraphView<'_> = QueryCallGraphView::new(&graph);
    let edges: Vec<disrobe_vulnmatch::CallGraphEdge> = view.call_edges();
    let rules_result: Result<RuleStore, RuleStoreError> = sink_rules();
    assert!(rules_result.is_ok(), "query sink rule must be valid");
    let Ok(rules) = rules_result else {
        return;
    };
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(128, 16);
    let report: disrobe_vulnmatch::Report = analyze(&view, &taint, &rules, &mut budget);
    let finding: Option<&disrobe_vulnmatch::Finding> = report.findings.first();

    assert_eq!(edges[0].kind, EdgeKind::UnresolvedIndirect);
    assert!(finding.is_some(), "sink must remain a candidate");
    let Some(finding) = finding else {
        return;
    };
    assert_eq!(finding.tier, FindingTier::ReachabilityUnknown);
    assert_eq!(
        finding.evidence.reachability,
        ReachabilityEvidence::ReachabilityUnknown {
            distance: 1,
            weakest_edge_soundness: disrobe_vulnmatch::EdgeSoundness::Unknown,
            unresolved_call_site: disrobe_vulnmatch::CallSiteId::new(
                "query:0000000000000100:0000000000000110",
            ),
        }
    );
    assert!(
        finding.witness_path.is_some(),
        "unknown reachability needs a witness"
    );
    assert!(!report.complete);
}

#[test]
fn query_call_graph_named_import_remains_a_direct_sink() {
    let graph: CallGraph = CallGraph {
        nodes: vec![
            CallGraphNode {
                name: String::from("main"),
                address: 0x100,
                is_export: true,
            },
            CallGraphNode {
                name: String::from("worker"),
                address: 0x200,
                is_export: false,
            },
        ],
        edges: vec![
            CallGraphEdge {
                caller: String::from("main"),
                caller_address: 0x100,
                call_site: 0x110,
                callee: String::from("worker"),
                callee_address: 0x200,
            },
            CallGraphEdge {
                caller: String::from("worker"),
                caller_address: 0x200,
                call_site: 0x210,
                callee: String::from("danger_sink"),
                callee_address: 0x300,
            },
        ],
    };
    let view: QueryCallGraphView<'_> = QueryCallGraphView::new(&graph);
    let edges: Vec<disrobe_vulnmatch::CallGraphEdge> = view.call_edges();
    let rules_result: Result<RuleStore, RuleStoreError> = sink_rules();
    assert!(rules_result.is_ok(), "query sink rule must be valid");
    let Ok(rules) = rules_result else {
        return;
    };
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(128, 16);
    let report: disrobe_vulnmatch::Report = analyze(&view, &taint, &rules, &mut budget);
    let finding: Option<&disrobe_vulnmatch::Finding> = report.findings.first();

    assert_eq!(edges[1].kind, EdgeKind::Direct { callee: None });
    assert!(
        finding.is_some(),
        "named import sink must remain a candidate"
    );
    let Some(finding) = finding else {
        return;
    };
    assert_eq!(finding.tier, FindingTier::Reachable);
    assert!(
        finding.witness_path.is_some(),
        "import sink must retain a witness"
    );
    assert!(!report.complete);
}

#[test]
fn query_call_graph_local_generated_name_keeps_the_resolved_symbol() {
    let graph: CallGraph = CallGraph {
        nodes: vec![
            CallGraphNode {
                name: String::from("main"),
                address: 0x100,
                is_export: true,
            },
            CallGraphNode {
                name: String::from("sub_300"),
                address: 0x300,
                is_export: false,
            },
        ],
        edges: vec![CallGraphEdge {
            caller: String::from("main"),
            caller_address: 0x100,
            call_site: 0x110,
            callee: String::from("sub_300"),
            callee_address: 0x300,
        }],
    };
    let view: QueryCallGraphView<'_> = QueryCallGraphView::new(&graph);
    let calls: Vec<disrobe_vulnmatch::DirectCall> = view.direct_calls();
    let edges: Vec<disrobe_vulnmatch::CallGraphEdge> = view.call_edges();

    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].resolved_callee,
        Some(disrobe_vulnmatch::ResolvedCallee::new("sub_300"))
    );
    assert_eq!(
        edges[0].kind,
        EdgeKind::Direct {
            callee: Some(function_id("sub_300", 0x300)),
        }
    );
}

#[test]
fn query_call_graph_uses_roots_when_no_export_is_available() {
    let graph: CallGraph = CallGraph {
        nodes: vec![
            CallGraphNode {
                name: String::from("root"),
                address: 0x100,
                is_export: false,
            },
            CallGraphNode {
                name: String::from("danger_sink"),
                address: 0x300,
                is_export: false,
            },
        ],
        edges: vec![CallGraphEdge {
            caller: String::from("root"),
            caller_address: 0x100,
            call_site: 0x110,
            callee: String::from("danger_sink"),
            callee_address: 0x300,
        }],
    };
    let view: QueryCallGraphView<'_> = QueryCallGraphView::new(&graph);
    let entries: Vec<FunctionId> = view.entry_points();
    let rules_result: Result<RuleStore, RuleStoreError> = sink_rules();
    assert!(rules_result.is_ok(), "query sink rule must be valid");
    let Ok(rules) = rules_result else {
        return;
    };
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(128, 16);
    let report: disrobe_vulnmatch::Report = analyze(&view, &taint, &rules, &mut budget);
    let finding: Option<&disrobe_vulnmatch::Finding> = report.findings.first();

    assert_eq!(entries, vec![function_id("root", 0x100)]);
    assert!(!view.entry_points_complete());
    assert!(finding.is_some(), "root sink must produce one finding");
    let Some(finding) = finding else {
        return;
    };
    assert_eq!(finding.tier, FindingTier::Reachable);
    assert!(
        finding.witness_path.is_some(),
        "root sink must retain a witness"
    );
    assert!(!report.complete);
}

#[test]
fn query_call_graph_root_fallback_preserves_an_unresolved_witness() {
    let graph: CallGraph = CallGraph {
        nodes: vec![
            CallGraphNode {
                name: String::from("root"),
                address: 0x100,
                is_export: false,
            },
            CallGraphNode {
                name: String::from("worker"),
                address: 0x200,
                is_export: false,
            },
            CallGraphNode {
                name: String::from("danger_sink"),
                address: 0x300,
                is_export: false,
            },
        ],
        edges: vec![
            CallGraphEdge {
                caller: String::from("root"),
                caller_address: 0x100,
                call_site: 0x110,
                callee: String::from("sub_180"),
                callee_address: 0x180,
            },
            CallGraphEdge {
                caller: String::from("worker"),
                caller_address: 0x200,
                call_site: 0x210,
                callee: String::from("worker"),
                callee_address: 0x200,
            },
            CallGraphEdge {
                caller: String::from("worker"),
                caller_address: 0x200,
                call_site: 0x220,
                callee: String::from("danger_sink"),
                callee_address: 0x300,
            },
        ],
    };
    let view: QueryCallGraphView<'_> = QueryCallGraphView::new(&graph);
    let entries: Vec<FunctionId> = view.entry_points();
    let rules_result: Result<RuleStore, RuleStoreError> = sink_rules();
    assert!(rules_result.is_ok(), "query sink rule must be valid");
    let Ok(rules) = rules_result else {
        return;
    };
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(128, 16);
    let report: disrobe_vulnmatch::Report = analyze(&view, &taint, &rules, &mut budget);
    let finding: Option<&disrobe_vulnmatch::Finding> = report.findings.first();

    assert_eq!(entries, vec![function_id("root", 0x100)]);
    assert!(finding.is_some(), "unknown sink must remain a candidate");
    let Some(finding) = finding else {
        return;
    };
    assert_eq!(finding.tier, FindingTier::ReachabilityUnknown);
    assert!(
        finding.witness_path.is_some(),
        "unknown reachability needs a witness"
    );
    assert!(!report.complete);
}
