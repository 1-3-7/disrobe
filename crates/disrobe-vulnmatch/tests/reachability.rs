use std::collections::BTreeSet;

use disrobe_vulnmatch::{
    AbstractArgument, ArgPredicate, Budget, CallGraphEdge, CallGraphView, CallSiteId, DirectCall,
    EdgeKind, EdgeSoundness, FindingTier, FunctionId, MAX_RESOLVED_INDIRECT_CALLEES_PER_SITE,
    ReachabilityEngine, ReachabilityEvidence, ReachabilityState, ResolvedCallee, RuleStore,
    Severity, TaintOracle, TaintStatus, TaintWitness, TaintWitnessStep, analyze,
};

#[derive(Debug, Clone)]
struct MockCallGraph {
    functions: Vec<FunctionId>,
    calls: Vec<DirectCall>,
    entries: Vec<FunctionId>,
}

impl CallGraphView for MockCallGraph {
    fn functions(&self) -> Vec<FunctionId> {
        self.functions.clone()
    }

    fn direct_calls(&self) -> Vec<DirectCall> {
        self.calls.clone()
    }

    fn entry_points(&self) -> Vec<FunctionId> {
        self.entries.clone()
    }
}

#[derive(Debug, Clone)]
struct IndirectMockCallGraph {
    direct_graph: MockCallGraph,
    edges: Vec<CallGraphEdge>,
}

impl CallGraphView for IndirectMockCallGraph {
    fn functions(&self) -> Vec<FunctionId> {
        self.direct_graph.functions()
    }

    fn direct_calls(&self) -> Vec<DirectCall> {
        self.direct_graph.direct_calls()
    }

    fn call_edges(&self) -> Vec<CallGraphEdge> {
        self.edges.clone()
    }

    fn entry_points(&self) -> Vec<FunctionId> {
        self.direct_graph.entry_points()
    }
}

#[derive(Debug, Clone, Copy)]
struct UnknownTaint;

impl TaintOracle for UnknownTaint {
    fn taint_status(
        &self,
        _source: &disrobe_vulnmatch::SourceClass,
        _site: &DirectCall,
    ) -> TaintStatus {
        TaintStatus::Unknown
    }
}

#[derive(Debug, Clone)]
struct FixedTaint {
    status: TaintStatus,
}

impl TaintOracle for FixedTaint {
    fn taint_status(
        &self,
        _source: &disrobe_vulnmatch::SourceClass,
        _site: &DirectCall,
    ) -> TaintStatus {
        self.status.clone()
    }
}

fn function(name: &str) -> FunctionId {
    FunctionId::new(name)
}

fn call(
    id: &str,
    caller: &str,
    callee_function: Option<&str>,
    callee_symbol: Option<&str>,
    arguments: Vec<AbstractArgument>,
) -> DirectCall {
    DirectCall::new(
        CallSiteId::new(id),
        function(caller),
        callee_function.map(function),
        callee_symbol.map(ResolvedCallee::new),
        arguments,
    )
}

fn edge(id: &str, caller: &str, kind: EdgeKind) -> CallGraphEdge {
    CallGraphEdge {
        id: CallSiteId::new(id),
        caller: function(caller),
        kind,
    }
}

fn sink_call(id: &str, caller: &str) -> DirectCall {
    call(
        id,
        caller,
        None,
        Some("strcpy"),
        vec![AbstractArgument::NonConstant, AbstractArgument::NonConstant],
    )
}

fn indirect_graph(kind: EdgeKind) -> IndirectMockCallGraph {
    IndirectMockCallGraph {
        direct_graph: MockCallGraph {
            functions: vec![function("main"), function("sink")],
            calls: vec![sink_call("sink-strcpy", "sink")],
            entries: vec![function("main")],
        },
        edges: vec![edge("main-dispatch", "main", kind)],
    }
}

fn indirect_finding(report: &disrobe_vulnmatch::Report) -> Option<&disrobe_vulnmatch::Finding> {
    report
        .findings
        .iter()
        .find(|candidate: &&disrobe_vulnmatch::Finding| {
            candidate.sink_site.id == CallSiteId::new("sink-strcpy")
        })
}

fn sample_graph() -> MockCallGraph {
    MockCallGraph {
        functions: vec![
            function("main"),
            function("reachable"),
            function("unreachable"),
        ],
        calls: vec![
            call(
                "main-to-reachable",
                "main",
                Some("reachable"),
                Some("reachable"),
                Vec::new(),
            ),
            call(
                "reachable-strcpy",
                "reachable",
                None,
                Some("strcpy"),
                vec![AbstractArgument::NonConstant, AbstractArgument::NonConstant],
            ),
            call(
                "unreachable-strcpy",
                "unreachable",
                None,
                Some("strcpy"),
                vec![AbstractArgument::NonConstant, AbstractArgument::NonConstant],
            ),
            call(
                "main-printf",
                "main",
                None,
                Some("printf"),
                vec![AbstractArgument::NonConstant],
            ),
        ],
        entries: vec![function("main")],
    }
}

#[test]
fn reachable_and_unreachable_sinks_keep_distinct_tiers_and_witnesses() {
    let graph: MockCallGraph = sample_graph();
    let rules: RuleStore = RuleStore::embedded();
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(128, 16);

    let report: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut budget);
    let reachable_strcpy: Option<&disrobe_vulnmatch::Finding> = report
        .findings
        .iter()
        .find(|finding| finding.sink_site.id == CallSiteId::new("reachable-strcpy"));
    assert!(
        reachable_strcpy.is_some(),
        "reachable strcpy finding must exist"
    );
    let Some(reachable_strcpy) = reachable_strcpy else {
        return;
    };
    let unreachable_strcpy: Option<&disrobe_vulnmatch::Finding> = report
        .findings
        .iter()
        .find(|finding| finding.sink_site.id == CallSiteId::new("unreachable-strcpy"));
    assert!(
        unreachable_strcpy.is_some(),
        "unreachable strcpy finding must exist"
    );
    let Some(unreachable_strcpy) = unreachable_strcpy else {
        return;
    };

    assert_eq!(reachable_strcpy.tier, FindingTier::Reachable);
    assert_eq!(unreachable_strcpy.tier, FindingTier::Present);
    assert!(reachable_strcpy.score > unreachable_strcpy.score);
    assert_ne!(reachable_strcpy.id, unreachable_strcpy.id);
    let reachable_witness: Option<&disrobe_vulnmatch::PathWitness> =
        reachable_strcpy.witness_path.as_ref();
    assert!(reachable_witness.is_some(), "reachable path must be stored");
    let Some(reachable_witness) = reachable_witness else {
        return;
    };
    assert_eq!(
        reachable_witness.functions,
        vec![function("main"), function("reachable")]
    );
    assert!(unreachable_strcpy.witness_path.is_none());
}

#[test]
fn source_required_rule_caps_at_reachable_when_taint_is_unknown() {
    let graph: MockCallGraph = sample_graph();
    let rules: RuleStore = RuleStore::embedded();
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(128, 16);

    let report: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut budget);
    let printf: Option<&disrobe_vulnmatch::Finding> = report
        .findings
        .iter()
        .find(|finding| finding.sink_site.id == CallSiteId::new("main-printf"));
    assert!(printf.is_some(), "printf finding must exist");
    let Some(printf) = printf else {
        return;
    };

    assert_eq!(printf.tier, FindingTier::Reachable);
    assert_eq!(printf.evidence.taint_status, Some(TaintStatus::Unknown));
    assert!(printf.witness_path.is_some());
}

#[test]
fn reports_are_byte_identical_across_repeated_analysis() {
    let graph: MockCallGraph = sample_graph();
    let rules: RuleStore = RuleStore::embedded();
    let taint: UnknownTaint = UnknownTaint;
    let mut first_budget: Budget = Budget::new(128, 16);
    let mut second_budget: Budget = Budget::new(128, 16);

    let first: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut first_budget);
    let second: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut second_budget);

    let first_json: Result<String, serde_json::Error> = first.to_json();
    let second_json: Result<String, serde_json::Error> = second.to_json();
    assert!(first_json.is_ok());
    assert!(second_json.is_ok());
    let Ok(first_json) = first_json else {
        return;
    };
    let Ok(second_json) = second_json else {
        return;
    };
    assert_eq!(first_json, second_json);
    assert_eq!(first.human(), second.human());
}

#[test]
fn unreachable_pattern_matches_are_suppressed_from_reachable_tiers() {
    let graph: MockCallGraph = sample_graph();
    let rules: RuleStore = RuleStore::embedded();
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(128, 16);

    let report: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut budget);
    let pattern_count: usize = report.findings.len();
    let reachable_count: usize = report
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.tier,
                FindingTier::Reachable | FindingTier::Confirmed
            )
        })
        .count();

    assert_eq!(pattern_count, 3);
    assert_eq!(reachable_count, 2);
    assert!(pattern_count > reachable_count);
}

#[test]
fn node_limit_bounds_large_graph_processing() {
    let functions: Vec<FunctionId> = (0..256)
        .map(|index: usize| function(&format!("function-{index:04}")))
        .collect();
    let calls: Vec<DirectCall> = (0..255)
        .map(|index: usize| {
            call(
                &format!("edge-{index:04}"),
                &format!("function-{index:04}"),
                Some(&format!("function-{:04}", index + 1)),
                Some(&format!("function-{:04}", index + 1)),
                Vec::new(),
            )
        })
        .collect();
    let graph: MockCallGraph = MockCallGraph {
        functions,
        calls,
        entries: vec![function("function-0000")],
    };
    let rules: RuleStore = RuleStore::embedded();
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(8, 64);

    let report: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut budget);

    assert_eq!(budget.nodes_used(), 8);
    assert!(budget.node_limit_reached());
    assert!(!report.complete);
}

#[test]
fn scc_reachability_keeps_a_direct_function_witness() {
    let graph: MockCallGraph = MockCallGraph {
        functions: vec![function("main"), function("alpha"), function("beta")],
        calls: vec![
            call(
                "main-alpha",
                "main",
                Some("alpha"),
                Some("alpha"),
                Vec::new(),
            ),
            call(
                "alpha-beta",
                "alpha",
                Some("beta"),
                Some("beta"),
                Vec::new(),
            ),
            call(
                "beta-alpha",
                "beta",
                Some("alpha"),
                Some("alpha"),
                Vec::new(),
            ),
            call(
                "beta-strcpy",
                "beta",
                None,
                Some("strcpy"),
                vec![AbstractArgument::NonConstant, AbstractArgument::NonConstant],
            ),
        ],
        entries: vec![function("main")],
    };
    let rules: RuleStore = RuleStore::embedded();
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(128, 16);

    let report: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut budget);
    let finding: Option<&disrobe_vulnmatch::Finding> = report
        .findings
        .iter()
        .find(|candidate| candidate.sink_site.id == CallSiteId::new("beta-strcpy"));
    assert!(finding.is_some(), "SCC sink must be found");
    let Some(finding) = finding else {
        return;
    };

    assert_eq!(finding.tier, FindingTier::Reachable);
    let witness: Option<&disrobe_vulnmatch::PathWitness> = finding.witness_path.as_ref();
    assert!(witness.is_some(), "SCC path must be stored");
    let Some(witness) = witness else {
        return;
    };
    assert_eq!(
        witness.functions,
        vec![function("main"), function("alpha"), function("beta")]
    );
}

#[test]
fn depth_exhaustion_reports_unknown_instead_of_unreachable() {
    let graph: MockCallGraph = MockCallGraph {
        functions: vec![function("main"), function("child")],
        calls: vec![
            call(
                "main-child",
                "main",
                Some("child"),
                Some("child"),
                Vec::new(),
            ),
            call(
                "child-strcpy",
                "child",
                None,
                Some("strcpy"),
                vec![AbstractArgument::NonConstant, AbstractArgument::NonConstant],
            ),
        ],
        entries: vec![function("main")],
    };
    let rules: RuleStore = RuleStore::embedded();
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(128, 0);

    let report: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut budget);
    let finding: Option<&disrobe_vulnmatch::Finding> = report
        .findings
        .iter()
        .find(|candidate| candidate.sink_site.id == CallSiteId::new("child-strcpy"));
    assert!(finding.is_some(), "depth-limited sink must be found");
    let Some(finding) = finding else {
        return;
    };

    assert_eq!(finding.tier, FindingTier::Unknown);
    assert!(finding.witness_path.is_none());
    assert!(budget.depth_limit_reached());
    assert!(!report.complete);
}

#[test]
fn unresolved_target_makes_downstream_sink_reachability_unknown() {
    let graph: MockCallGraph = MockCallGraph {
        functions: vec![function("main"), function("sink")],
        calls: vec![
            call("main-dispatch", "main", None, None, Vec::new()),
            sink_call("sink-strcpy", "sink"),
        ],
        entries: vec![function("main")],
    };
    let rules: RuleStore = RuleStore::embedded();
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(128, 16);

    let report: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut budget);
    let finding: Option<&disrobe_vulnmatch::Finding> = indirect_finding(&report);

    assert!(finding.is_some(), "downstream sink finding must exist");
    let Some(finding) = finding else {
        return;
    };
    assert_eq!(finding.tier, FindingTier::ReachabilityUnknown);
    assert!(!report.complete);
}

#[test]
fn resolved_indirect_sink_has_a_medium_soundness_witness() {
    let candidates: BTreeSet<FunctionId> = BTreeSet::from([function("sink")]);
    let graph: IndirectMockCallGraph = indirect_graph(EdgeKind::ResolvedIndirect { candidates });
    let rules: RuleStore = RuleStore::embedded();
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(128, 16);

    let report: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut budget);
    let finding: Option<&disrobe_vulnmatch::Finding> = indirect_finding(&report);

    assert!(finding.is_some(), "indirect sink finding must exist");
    let Some(finding) = finding else {
        return;
    };
    let witness: Option<&disrobe_vulnmatch::PathWitness> = finding.witness_path.as_ref();

    assert_eq!(finding.tier, FindingTier::Reachable);
    assert!(witness.is_some(), "resolved indirect witness must exist");
    let Some(witness) = witness else {
        return;
    };
    assert_eq!(witness.functions, vec![function("main"), function("sink")]);
    assert_eq!(witness.weakest_edge_soundness, EdgeSoundness::Medium);
    assert_eq!(
        finding.evidence.reachability,
        ReachabilityEvidence::Reachable {
            distance: 1,
            weakest_edge_soundness: EdgeSoundness::Medium,
        }
    );
}

#[test]
fn unresolved_indirect_sink_is_reachability_unknown_with_a_witness() {
    let graph: IndirectMockCallGraph = indirect_graph(EdgeKind::UnresolvedIndirect);
    let rules: RuleStore = RuleStore::embedded();
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(128, 16);

    let report: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut budget);
    let finding: Option<&disrobe_vulnmatch::Finding> = indirect_finding(&report);

    assert!(finding.is_some(), "indirect sink finding must exist");
    let Some(finding) = finding else {
        return;
    };
    let witness: Option<&disrobe_vulnmatch::PathWitness> = finding.witness_path.as_ref();

    assert_eq!(finding.tier, FindingTier::ReachabilityUnknown);
    assert_ne!(finding.tier, FindingTier::Reachable);
    assert_ne!(finding.tier, FindingTier::Present);
    assert!(witness.is_some(), "unresolved indirect witness must exist");
    let Some(witness) = witness else {
        return;
    };
    assert_eq!(witness.functions, vec![function("main")]);
    assert_eq!(witness.weakest_edge_soundness, EdgeSoundness::Unknown);
    assert_eq!(
        witness.terminal_unresolved_call,
        Some(CallSiteId::new("main-dispatch"))
    );
    assert_eq!(
        finding.evidence.reachability,
        ReachabilityEvidence::ReachabilityUnknown {
            distance: 1,
            weakest_edge_soundness: EdgeSoundness::Unknown,
            unresolved_call_site: CallSiteId::new("main-dispatch"),
        }
    );
}

#[test]
fn direct_sink_has_a_high_soundness_witness() {
    let graph: IndirectMockCallGraph = indirect_graph(EdgeKind::Direct {
        callee: Some(function("sink")),
    });
    let rules: RuleStore = RuleStore::embedded();
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(128, 16);

    let report: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut budget);
    let finding: Option<&disrobe_vulnmatch::Finding> = indirect_finding(&report);

    assert!(finding.is_some(), "indirect sink finding must exist");
    let Some(finding) = finding else {
        return;
    };
    let witness: Option<&disrobe_vulnmatch::PathWitness> = finding.witness_path.as_ref();

    assert_eq!(finding.tier, FindingTier::Reachable);
    assert!(witness.is_some(), "direct witness must exist");
    let Some(witness) = witness else {
        return;
    };
    assert_eq!(witness.functions, vec![function("main"), function("sink")]);
    assert_eq!(witness.weakest_edge_soundness, EdgeSoundness::High);
    assert_eq!(
        finding.evidence.reachability,
        ReachabilityEvidence::Reachable {
            distance: 1,
            weakest_edge_soundness: EdgeSoundness::High,
        }
    );
}

#[test]
fn over_cap_indirect_candidates_collapse_to_bounded_reachability_unknown() {
    let mut candidates: BTreeSet<FunctionId> = BTreeSet::new();
    for index in 0..MAX_RESOLVED_INDIRECT_CALLEES_PER_SITE {
        candidates.insert(function(&format!("candidate-{index:04}")));
    }
    candidates.insert(function("sink"));
    let graph: IndirectMockCallGraph = indirect_graph(EdgeKind::ResolvedIndirect { candidates });
    let rules: RuleStore = RuleStore::embedded();
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::with_step_limit(128, 16, 20);

    let report: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut budget);
    let finding: Option<&disrobe_vulnmatch::Finding> = indirect_finding(&report);

    assert!(finding.is_some(), "indirect sink finding must exist");
    let Some(finding) = finding else {
        return;
    };
    assert_eq!(finding.tier, FindingTier::ReachabilityUnknown);
    assert!(!budget.step_limit_reached());
}

#[test]
fn indirect_reports_are_byte_identical_across_repeated_analysis() {
    let candidates: BTreeSet<FunctionId> = BTreeSet::from([function("sink")]);
    let graph: IndirectMockCallGraph = indirect_graph(EdgeKind::ResolvedIndirect { candidates });
    let rules: RuleStore = RuleStore::embedded();
    let taint: UnknownTaint = UnknownTaint;
    let mut first_budget: Budget = Budget::new(128, 16);
    let mut second_budget: Budget = Budget::new(128, 16);

    let first: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut first_budget);
    let second: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut second_budget);
    let first_json: Result<String, serde_json::Error> = first.to_json();
    let second_json: Result<String, serde_json::Error> = second.to_json();

    assert!(first_json.is_ok());
    assert!(second_json.is_ok());
    let Ok(first_json) = first_json else {
        return;
    };
    let Ok(second_json) = second_json else {
        return;
    };
    assert_eq!(first_json, second_json);
    assert_eq!(first.human(), second.human());
}

#[test]
fn direct_only_missing_callee_sites_consume_the_reachability_budget() {
    let graph: MockCallGraph = MockCallGraph {
        functions: vec![function("main"), function("child")],
        calls: vec![
            call(
                "main-child",
                "main",
                Some("child"),
                Some("child"),
                Vec::new(),
            ),
            call("main-external", "main", None, Some("external"), Vec::new()),
        ],
        entries: vec![function("main")],
    };
    let mut budget: Budget = Budget::with_step_limit(128, 16, 7);

    let result: disrobe_vulnmatch::ReachabilityResult =
        ReachabilityEngine::analyze(&graph, &mut budget);

    assert_eq!(result.state(&function("child")), ReachabilityState::Unknown);
    assert!(!result.complete);
    assert!(budget.step_limit_reached());
}

#[test]
fn unresolved_indirect_edge_respects_the_depth_limit() {
    let graph: IndirectMockCallGraph = indirect_graph(EdgeKind::UnresolvedIndirect);
    let rules: RuleStore = RuleStore::embedded();
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(128, 0);

    let report: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut budget);
    let finding: Option<&disrobe_vulnmatch::Finding> = indirect_finding(&report);

    assert!(finding.is_some(), "indirect sink finding must exist");
    let Some(finding) = finding else {
        return;
    };
    assert_eq!(finding.tier, FindingTier::Unknown);
    assert!(finding.witness_path.is_none());
    assert!(budget.depth_limit_reached());
    assert!(!report.complete);
}

#[test]
fn source_required_finding_with_absent_taint_remains_present_with_reachability_evidence() {
    let graph: MockCallGraph = sample_graph();
    let rules: RuleStore = RuleStore::embedded();
    let taint: FixedTaint = FixedTaint {
        status: TaintStatus::Absent,
    };
    let mut budget: Budget = Budget::new(128, 16);

    let report: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut budget);
    let finding: Option<&disrobe_vulnmatch::Finding> =
        report
            .findings
            .iter()
            .find(|candidate: &&disrobe_vulnmatch::Finding| {
                candidate.sink_site.id == CallSiteId::new("main-printf")
            });

    assert!(finding.is_some(), "source-required finding must exist");
    let Some(finding) = finding else {
        return;
    };
    assert_eq!(finding.tier, FindingTier::Present);
    assert!(finding.witness_path.is_some());
    assert_eq!(finding.evidence.taint_status, Some(TaintStatus::Absent));
    assert_eq!(
        finding.evidence.reachability,
        ReachabilityEvidence::Reachable {
            distance: 0,
            weakest_edge_soundness: EdgeSoundness::High,
        }
    );
}

#[test]
fn indeterminate_arguments_keep_possible_findings_and_mark_the_report_incomplete() {
    let graph: MockCallGraph = MockCallGraph {
        functions: vec![function("main")],
        calls: vec![
            call(
                "unknown-strcpy",
                "main",
                None,
                Some("strcpy"),
                vec![AbstractArgument::NonConstant, AbstractArgument::Unknown],
            ),
            call("missing-strcpy", "main", None, Some("strcpy"), Vec::new()),
            call(
                "constant-strcpy",
                "main",
                None,
                Some("strcpy"),
                vec![AbstractArgument::NonConstant, AbstractArgument::Constant],
            ),
        ],
        entries: vec![function("main")],
    };
    let rules: RuleStore = RuleStore::embedded();
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(128, 16);

    let report: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut budget);
    let matched_sites: BTreeSet<CallSiteId> = report
        .findings
        .iter()
        .map(|finding: &disrobe_vulnmatch::Finding| finding.sink_site.id.clone())
        .collect();

    assert_eq!(
        matched_sites,
        BTreeSet::from([
            CallSiteId::new("missing-strcpy"),
            CallSiteId::new("unknown-strcpy"),
        ])
    );
    assert!(!report.complete);
    let unknown_finding: Option<&disrobe_vulnmatch::Finding> =
        report
            .findings
            .iter()
            .find(|finding: &&disrobe_vulnmatch::Finding| {
                finding.sink_site.id == CallSiteId::new("unknown-strcpy")
            });
    assert!(
        unknown_finding.is_some(),
        "indeterminate finding must exist"
    );
    let Some(unknown_finding) = unknown_finding else {
        return;
    };
    assert_eq!(unknown_finding.tier, FindingTier::Unknown);
    assert!(unknown_finding.witness_path.is_some());
    assert!(unknown_finding.evidence.matched_constraints.is_empty());
    assert_eq!(
        unknown_finding.evidence.indeterminate_constraints,
        vec![ArgPredicate::IsNotConstant(1)]
    );
}

#[test]
fn duplicate_direct_calls_produce_one_stable_finding() {
    let sink: DirectCall = sink_call("main-strcpy", "main");
    let graph: MockCallGraph = MockCallGraph {
        functions: vec![function("main")],
        calls: vec![sink.clone(), sink],
        entries: vec![function("main")],
    };
    let rules: RuleStore = RuleStore::embedded();
    let taint: UnknownTaint = UnknownTaint;
    let mut budget: Budget = Budget::new(128, 16);

    let report: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut budget);
    let ids: BTreeSet<disrobe_vulnmatch::FindingId> = report
        .findings
        .iter()
        .map(|finding: &disrobe_vulnmatch::Finding| finding.id.clone())
        .collect();

    assert_eq!(report.findings.len(), 1);
    assert_eq!(ids.len(), report.findings.len());
}

#[test]
fn edge_from_unknown_caller_marks_reachability_incomplete() {
    let graph: IndirectMockCallGraph = IndirectMockCallGraph {
        direct_graph: MockCallGraph {
            functions: vec![function("main"), function("sink")],
            calls: vec![sink_call("sink-strcpy", "sink")],
            entries: vec![function("main")],
        },
        edges: vec![edge(
            "phantom-dispatch",
            "phantom",
            EdgeKind::UnresolvedIndirect,
        )],
    };
    let mut budget: Budget = Budget::new(128, 16);

    let result: disrobe_vulnmatch::ReachabilityResult =
        ReachabilityEngine::analyze(&graph, &mut budget);

    assert!(!result.complete);
    assert_eq!(result.state(&function("sink")), ReachabilityState::Unknown);
}

#[test]
fn duplicate_call_edges_do_not_consume_extra_reachability_budget() {
    let call: DirectCall = call("main-external", "main", None, Some("external"), Vec::new());
    let graph: MockCallGraph = MockCallGraph {
        functions: vec![function("main")],
        calls: vec![call.clone(), call],
        entries: vec![function("main")],
    };
    let mut budget: Budget = Budget::with_step_limit(128, 16, 2);

    let result: disrobe_vulnmatch::ReachabilityResult =
        ReachabilityEngine::analyze(&graph, &mut budget);

    assert!(result.complete);
    assert!(!budget.step_limit_reached());
}

#[test]
fn present_taint_witness_confirms_a_reachable_source_required_finding() {
    let graph: MockCallGraph = sample_graph();
    let rules: RuleStore = RuleStore::embedded();
    let witness: Result<TaintWitness, disrobe_vulnmatch::TaintWitnessError> =
        TaintWitness::from_steps(vec![TaintWitnessStep::new(
            0x100,
            "argument-0-from-request",
            "source",
        )]);
    assert!(witness.is_ok(), "nonempty taint witness path must be valid");
    let Ok(witness) = witness else {
        return;
    };
    let taint: FixedTaint = FixedTaint {
        status: TaintStatus::Present(witness.clone()),
    };
    let mut budget: Budget = Budget::new(128, 16);

    let report: disrobe_vulnmatch::Report = analyze(&graph, &taint, &rules, &mut budget);
    let finding: Option<&disrobe_vulnmatch::Finding> =
        report
            .findings
            .iter()
            .find(|candidate: &&disrobe_vulnmatch::Finding| {
                candidate.sink_site.id == CallSiteId::new("main-printf")
            });

    assert!(finding.is_some(), "source-required finding must exist");
    let Some(finding) = finding else {
        return;
    };
    assert_eq!(finding.tier, FindingTier::Confirmed);
    assert_eq!(
        finding.evidence.taint_status,
        Some(TaintStatus::Present(witness))
    );
    assert!(finding.witness_path.is_some());
}

#[test]
fn empty_taint_witness_is_rejected() {
    let witness: Result<TaintWitness, disrobe_vulnmatch::TaintWitnessError> =
        TaintWitness::from_steps(Vec::new());

    assert!(witness.is_err());
}

#[test]
fn whitespace_taint_witness_deserialization_is_rejected() {
    let witness: Result<TaintWitness, serde_json::Error> = serde_json::from_str("[]");

    assert!(witness.is_err());
}

#[test]
fn severity_and_finding_tier_order_follow_increasing_precedence() {
    assert!(Severity::Critical > Severity::Low);
    assert!(FindingTier::Confirmed > FindingTier::Reachable);
}
