use std::collections::BTreeSet;

use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_query::model::{CallGraph, CallGraphEdge, CallGraphNode};
use disrobe_taint::{TaintConfig, TaintFinding, TaintReport, TaintStep};
use disrobe_vulnmatch::{
    ArgPredicate, Budget, CallSiteId, DirectCall, FindingTier, FunctionId, QueryCallGraphView,
    ResolvedCallee, Rule, RuleStore, Severity, SinkSignature, SourceClass, TaintOracle,
    TaintReportOracle, TaintStatus, analyze_with_taint, taint_config_for_rules,
};

const ENTRY_ADDRESS: u64 = 0x100;
const RECV_ADDRESS: u64 = 0xa000;
const SYSTEM_ADDRESS: u64 = 0xb000;
const ESCAPE_ADDRESS: u64 = 0xc000;
const SOURCE_SITE: u64 = 0x100;
const SINK_SITE: u64 = 0x118;
const SANITIZER_SITE: u64 = 0x118;
const SANITIZED_SINK_SITE: u64 = 0x128;

#[derive(Debug, Clone, Copy)]
enum FlowCase {
    Tainted,
    Untainted,
    Sanitized,
}

fn instruction(address: u64, op: NirOp, mnemonic: &str, operands: &[&str]) -> NirInstr {
    NirInstr {
        address,
        op,
        mnemonic: mnemonic.to_owned(),
        operands: operands
            .iter()
            .map(|operand: &&str| (*operand).to_owned())
            .collect(),
        reads_memory: false,
        writes_memory: false,
        byte_width: false,
        source: SourceRef::new(SourceLang::NativeX86, address),
    }
}

fn external_call(address: u64, symbol: &str, operands: &[&str]) -> NirInstr {
    instruction(
        address,
        NirOp::ExternCall {
            symbol: symbol.to_owned(),
        },
        "call",
        operands,
    )
}

fn module(case: FlowCase) -> NirModule {
    let instructions: Vec<NirInstr> = match case {
        FlowCase::Tainted => vec![
            external_call(SOURCE_SITE, "recv", &[]),
            instruction(
                0x108,
                NirOp::BinOp { op: BinaryOp::Add },
                "mov",
                &["rdi", "rax"],
            ),
            external_call(SINK_SITE, "system", &["rdi"]),
            instruction(0x120, NirOp::Return, "ret", &[]),
        ],
        FlowCase::Untainted => vec![
            external_call(SOURCE_SITE, "recv", &[]),
            instruction(0x108, NirOp::Const, "mov", &["rdi", "0x2a"]),
            external_call(SINK_SITE, "system", &["rdi"]),
            instruction(0x120, NirOp::Return, "ret", &[]),
        ],
        FlowCase::Sanitized => vec![
            external_call(SOURCE_SITE, "recv", &[]),
            instruction(
                0x108,
                NirOp::BinOp { op: BinaryOp::Add },
                "mov",
                &["rdi", "rax"],
            ),
            external_call(SANITIZER_SITE, "escape_shell", &["rdi"]),
            instruction(
                0x120,
                NirOp::BinOp { op: BinaryOp::Add },
                "mov",
                &["rdi", "rax"],
            ),
            external_call(SANITIZED_SINK_SITE, "system", &["rax"]),
            instruction(0x130, NirOp::Return, "ret", &[]),
        ],
    };
    NirModule {
        source_hash: [3u8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![NirFunction {
            name: "entry".to_owned(),
            address: ENTRY_ADDRESS,
            end: 0x140,
            is_export: true,
            instructions,
            source: SourceRef::new(SourceLang::NativeX86, ENTRY_ADDRESS),
        }],
        symbols: vec![
            NirSymbol {
                address: RECV_ADDRESS,
                name: "recv".to_owned(),
                kind: SymbolKind::Import,
            },
            NirSymbol {
                address: SYSTEM_ADDRESS,
                name: "system".to_owned(),
                kind: SymbolKind::Import,
            },
            NirSymbol {
                address: ESCAPE_ADDRESS,
                name: "escape_shell".to_owned(),
                kind: SymbolKind::Import,
            },
        ],
    }
}

fn call_graph(sink_site: u64) -> CallGraph {
    CallGraph {
        nodes: vec![
            CallGraphNode {
                name: "entry".to_owned(),
                address: ENTRY_ADDRESS,
                is_export: true,
            },
            CallGraphNode {
                name: "system".to_owned(),
                address: SYSTEM_ADDRESS,
                is_export: false,
            },
        ],
        edges: vec![CallGraphEdge {
            caller: "entry".to_owned(),
            caller_address: ENTRY_ADDRESS,
            call_site: sink_site,
            callee: "system".to_owned(),
            callee_address: SYSTEM_ADDRESS,
        }],
    }
}

fn source_required_system_rule() -> Result<RuleStore, disrobe_vulnmatch::RuleStoreError> {
    RuleStore::from_rules(vec![Rule {
        id: "cwe-78-tainted-system".to_owned(),
        cwe: "CWE-78".to_owned(),
        severity: Severity::Critical,
        sink: SinkSignature::ResolvedSymbol {
            canonical_name: "system".to_owned(),
            aliases: BTreeSet::new(),
        },
        requires_source: Some(SourceClass::UserControlled),
        arg_constraints: Vec::new(),
    }])
}

fn source_required_system_config() -> TaintConfig {
    let rules_result: Result<RuleStore, disrobe_vulnmatch::RuleStoreError> =
        source_required_system_rule();
    assert!(rules_result.is_ok(), "test rule must be valid");
    let Ok(rules) = rules_result else {
        return TaintConfig::new();
    };
    taint_config_for_rules(&rules, std::iter::empty::<&str>())
}

fn report_for(case: FlowCase, sanitizers: &[&str]) -> disrobe_vulnmatch::Report {
    let rules_result: Result<RuleStore, disrobe_vulnmatch::RuleStoreError> =
        source_required_system_rule();
    assert!(rules_result.is_ok(), "test rule must be valid");
    let Ok(rules) = rules_result else {
        return disrobe_vulnmatch::Report {
            findings: Vec::new(),
            complete: false,
        };
    };
    let sink_site: u64 = match case {
        FlowCase::Sanitized => SANITIZED_SINK_SITE,
        FlowCase::Tainted | FlowCase::Untainted => SINK_SITE,
    };
    let graph: CallGraph = call_graph(sink_site);
    let view: QueryCallGraphView<'_> = QueryCallGraphView::new(&graph);
    let module: NirModule = module(case);
    let mut budget: Budget = Budget::new(128, 16);
    analyze_with_taint(
        &view,
        &module,
        &rules,
        sanitizers.iter().copied(),
        &mut budget,
    )
}

#[test]
fn tainted_reachable_query_sink_is_confirmed_with_a_taint_path() {
    let report: disrobe_vulnmatch::Report = report_for(FlowCase::Tainted, &[]);
    let finding: Option<&disrobe_vulnmatch::Finding> = report.findings.first();

    assert!(finding.is_some(), "the sink candidate must be reported");
    let Some(finding) = finding else {
        return;
    };
    assert_eq!(finding.tier, FindingTier::Confirmed);
    let status: Option<&TaintStatus> = finding.evidence.taint_status.as_ref();
    assert!(
        status.is_some(),
        "confirmed findings must retain taint evidence"
    );
    let Some(TaintStatus::Present(witness)) = status else {
        return;
    };
    assert!(
        witness
            .steps()
            .iter()
            .any(|step| step.address == SOURCE_SITE && step.symbol == "recv"),
        "the stored path must retain the source step: {witness:?}"
    );
    assert!(
        witness
            .steps()
            .iter()
            .any(|step| step.address == SINK_SITE && step.symbol == "system"),
        "the stored path must retain the sink step: {witness:?}"
    );
}

#[test]
fn argument_sensitive_rule_stays_unknown_without_sink_argument_identity() {
    let rules_result: Result<RuleStore, disrobe_vulnmatch::RuleStoreError> =
        RuleStore::from_rules(vec![Rule {
            id: "cwe-78-tainted-system-argument".to_owned(),
            cwe: "CWE-78".to_owned(),
            severity: Severity::Critical,
            sink: SinkSignature::ResolvedSymbol {
                canonical_name: "system".to_owned(),
                aliases: BTreeSet::new(),
            },
            requires_source: Some(SourceClass::UserControlled),
            arg_constraints: vec![ArgPredicate::IsNotConstant(0)],
        }]);
    assert!(rules_result.is_ok(), "test rule must be valid");
    let Ok(rules) = rules_result else {
        return;
    };
    let graph: CallGraph = call_graph(SINK_SITE);
    let view: QueryCallGraphView<'_> = QueryCallGraphView::new(&graph);
    let module: NirModule = module(FlowCase::Tainted);
    let mut budget: Budget = Budget::new(128, 16);
    let report: disrobe_vulnmatch::Report = analyze_with_taint(
        &view,
        &module,
        &rules,
        std::iter::empty::<&str>(),
        &mut budget,
    );
    let finding: Option<&disrobe_vulnmatch::Finding> = report.findings.first();

    assert!(finding.is_some(), "the sink candidate must be reported");
    let Some(finding) = finding else {
        return;
    };
    assert_eq!(finding.tier, FindingTier::Unknown);
    assert!(matches!(
        finding.evidence.taint_status,
        Some(TaintStatus::Present(_))
    ));
}

#[test]
fn reachable_query_sink_without_taint_is_present() {
    let report: disrobe_vulnmatch::Report = report_for(FlowCase::Untainted, &[]);
    let finding: Option<&disrobe_vulnmatch::Finding> = report.findings.first();

    assert!(finding.is_some(), "the sink candidate must be reported");
    let Some(finding) = finding else {
        return;
    };
    assert_eq!(finding.tier, FindingTier::Present);
    assert_eq!(finding.evidence.taint_status, Some(TaintStatus::Absent));
}

#[test]
fn sanitizer_on_the_real_taint_path_does_not_confirm_the_sink() {
    let report: disrobe_vulnmatch::Report = report_for(FlowCase::Sanitized, &["escape_shell"]);
    let finding: Option<&disrobe_vulnmatch::Finding> = report.findings.first();

    assert!(finding.is_some(), "the sink candidate must be reported");
    let Some(finding) = finding else {
        return;
    };
    assert_ne!(finding.tier, FindingTier::Confirmed);
    assert_eq!(finding.tier, FindingTier::Present);
    assert_eq!(finding.evidence.taint_status, Some(TaintStatus::Absent));
}

#[test]
fn sanitizer_steps_in_a_reported_path_are_not_confirming_evidence() {
    let report: TaintReport = TaintReport::new(vec![TaintFinding {
        function: "entry".to_owned(),
        function_address: ENTRY_ADDRESS,
        source_site: SOURCE_SITE,
        source_symbol: "recv".to_owned(),
        sink_site: SINK_SITE,
        sink_symbol: "system".to_owned(),
        path: vec![
            TaintStep {
                address: SOURCE_SITE,
                symbol: "recv".to_owned(),
                kind: "source".to_owned(),
            },
            TaintStep {
                address: SANITIZER_SITE,
                symbol: "escape_shell".to_owned(),
                kind: "sanitize".to_owned(),
            },
            TaintStep {
                address: SINK_SITE,
                symbol: "system".to_owned(),
                kind: "sink".to_owned(),
            },
        ],
    }]);
    let config: TaintConfig = source_required_system_config();
    let adapter: TaintReportOracle = TaintReportOracle::new(report, &config);
    let site: DirectCall = DirectCall::new(
        CallSiteId::new("query:0000000000000100:0000000000000118"),
        FunctionId::new("query:0000000000000100:entry"),
        Some(FunctionId::new("query:000000000000b000:system")),
        Some(ResolvedCallee::new("system")),
        Vec::new(),
    );
    let status: TaintStatus = adapter.taint_status(&SourceClass::UserControlled, &site);

    assert_eq!(status, TaintStatus::Absent);
}

#[test]
fn evidence_from_another_query_caller_does_not_confirm_the_sink() {
    let report: TaintReport = TaintReport::new(vec![TaintFinding {
        function: "other".to_owned(),
        function_address: 0x200,
        source_site: SOURCE_SITE,
        source_symbol: "recv".to_owned(),
        sink_site: SINK_SITE,
        sink_symbol: "system".to_owned(),
        path: vec![
            TaintStep {
                address: SOURCE_SITE,
                symbol: "recv".to_owned(),
                kind: "source".to_owned(),
            },
            TaintStep {
                address: SINK_SITE,
                symbol: "system".to_owned(),
                kind: "sink".to_owned(),
            },
        ],
    }]);
    let config: TaintConfig = source_required_system_config();
    let adapter: TaintReportOracle = TaintReportOracle::new(report, &config);
    let site: DirectCall = DirectCall::new(
        CallSiteId::new("query:0000000000000100:0000000000000118"),
        FunctionId::new("query:0000000000000100:entry"),
        Some(FunctionId::new("query:000000000000b000:system")),
        Some(ResolvedCallee::new("system")),
        Vec::new(),
    );
    let status: TaintStatus = adapter.taint_status(&SourceClass::UserControlled, &site);

    assert_eq!(status, TaintStatus::Absent);
}

#[test]
fn report_without_the_required_source_configuration_is_indeterminate() {
    let report: TaintReport = TaintReport::empty();
    let config: TaintConfig = TaintConfig::new().with_sink("system");
    let adapter: TaintReportOracle = TaintReportOracle::new(report, &config);
    let site: DirectCall = DirectCall::new(
        CallSiteId::new("query:0000000000000100:0000000000000118"),
        FunctionId::new("query:0000000000000100:entry"),
        Some(FunctionId::new("query:000000000000b000:system")),
        Some(ResolvedCallee::new("system")),
        Vec::new(),
    );
    let status: TaintStatus = adapter.taint_status(&SourceClass::UserControlled, &site);

    assert_eq!(status, TaintStatus::Unknown);
}

#[test]
fn query_function_names_with_colons_retain_taint_correlation() {
    let report: TaintReport = TaintReport::new(vec![TaintFinding {
        function: "namespace::entry".to_owned(),
        function_address: ENTRY_ADDRESS,
        source_site: SOURCE_SITE,
        source_symbol: "recv".to_owned(),
        sink_site: SINK_SITE,
        sink_symbol: "system".to_owned(),
        path: vec![
            TaintStep {
                address: SOURCE_SITE,
                symbol: "recv".to_owned(),
                kind: "source".to_owned(),
            },
            TaintStep {
                address: SINK_SITE,
                symbol: "system".to_owned(),
                kind: "sink".to_owned(),
            },
        ],
    }]);
    let config: TaintConfig = source_required_system_config();
    let adapter: TaintReportOracle = TaintReportOracle::new(report, &config);
    let site: DirectCall = DirectCall::new(
        CallSiteId::new("query:0000000000000100:0000000000000118"),
        FunctionId::new("query:0000000000000100:namespace::entry"),
        Some(FunctionId::new("query:000000000000b000:system")),
        Some(ResolvedCallee::new("system")),
        Vec::new(),
    );
    let status: TaintStatus = adapter.taint_status(&SourceClass::UserControlled, &site);

    assert!(matches!(status, TaintStatus::Present(_)));
}
