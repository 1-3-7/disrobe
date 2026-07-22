use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_ir::Envelope;
use disrobe_ir::payload::{DisasmPayload, decode_disasm};
use disrobe_nir::{NirModule, decode_nir};
use disrobe_pass_native::build_disasm_payload;
use disrobe_query::{CallGraph, Module, disasm_to_nir};
use disrobe_taint::{TaintConfig, TaintReport};
use disrobe_vulnmatch::{
    Budget, Finding, FindingTier, FunctionId, PathWitness, QueryCallGraphView, Report, RuleStore,
    Severity, TaintReportOracle, taint_config_for_rules,
};

use crate::cli::output::{self, OutputFormat};
use crate::cli::sarif::{
    ArtifactLocation, Driver, Location, Message, MultiformatMessageString, PhysicalLocation,
    ReportingDescriptor, SarifLevel, SarifLog, SarifResult,
};

const MAX_ANALYSIS_NODES: usize = 50_000;
const MAX_ANALYSIS_DEPTH: usize = 128;
const MAX_ANALYSIS_STEPS: usize = 2_000_000;
const INCOMPLETE_ANALYSIS_RULE_ID: &str = "disrobe.vulnmatch.analysis-incomplete";

#[derive(Debug)]
struct LoadedModule {
    query: Module,
    nir: NirModule,
}

#[derive(Debug)]
struct AnalysisResult {
    report: Report,
    budget: Budget,
}

pub(crate) fn run(input: PathBuf, fmt: OutputFormat) -> miette::Result<()> {
    let module: LoadedModule = load_module(&input)?;
    let result: AnalysisResult = analyze_module(&module);
    match fmt {
        OutputFormat::Sarif => output::emit_sarif_log(&report_to_sarif(&input, &result.report)),
        _ => output::emit(fmt, &result.report, || render_text(&input, &result)),
    }
}

fn load_module(input: &Path) -> miette::Result<LoadedModule> {
    let bytes: Vec<u8> = std::fs::read(input)
        .map_err(|e| miette::miette!("DR-CLI-0855: cannot read {}: {e}", input.display()))?;
    if let Ok(env) = Envelope::decode(&bytes) {
        return module_from_envelope(&env, input);
    }
    let payload: DisasmPayload = build_disasm_payload(&bytes).map_err(|e| {
        miette::miette!(
            "DR-CLI-0856: {} is neither a Disasm- or Mir-rung .dr envelope nor a disassemblable native binary: {e}",
            input.display()
        )
    })?;
    Ok(LoadedModule {
        query: Module::from_disasm(&payload),
        nir: disasm_to_nir(&payload),
    })
}

fn module_from_envelope(env: &Envelope, input: &Path) -> miette::Result<LoadedModule> {
    let query: Module = disrobe_query::module_from_envelope(env).map_err(|e| {
        miette::miette!(
            "DR-CLI-0857: {} is a .dr envelope but not queryable: {e}",
            input.display()
        )
    })?;
    let nir: NirModule = match env.rung {
        disrobe_core::Rung::Disasm => {
            let payload: DisasmPayload = decode_disasm(&env.hot).map_err(|e| {
                miette::miette!(
                    "DR-CLI-0858: {} is a Disasm-rung .dr envelope but the payload did not decode: {e}",
                    input.display()
                )
            })?;
            disasm_to_nir(&payload)
        }
        disrobe_core::Rung::Mir => decode_nir(&env.hot).map_err(|e| {
            miette::miette!(
                "DR-CLI-0859: {} is a Mir-rung .dr envelope but the NIR payload did not decode: {e}",
                input.display()
            )
        })?,
        other => {
            return Err(miette::miette!(
                "DR-CLI-0860: {} is a {other:?}-rung .dr envelope; vulnmatch needs a Disasm- or Mir-rung envelope",
                input.display()
            ));
        }
    };
    Ok(LoadedModule { query, nir })
}

fn analyze_module(module: &LoadedModule) -> AnalysisResult {
    let graph: CallGraph = module.query.call_graph();
    let call_graph: QueryCallGraphView<'_> = QueryCallGraphView::new(&graph);
    let rules: RuleStore = RuleStore::embedded();
    let config: TaintConfig = taint_config_for_rules(&rules, std::iter::empty::<&str>());
    let taint_report: TaintReport = disrobe_taint::analyze(&module.nir, &config);
    let taint: TaintReportOracle = TaintReportOracle::new(taint_report, &config);
    let mut budget: Budget =
        Budget::with_step_limit(MAX_ANALYSIS_NODES, MAX_ANALYSIS_DEPTH, MAX_ANALYSIS_STEPS);
    let report: Report = disrobe_vulnmatch::analyze(&call_graph, &taint, &rules, &mut budget);
    AnalysisResult { report, budget }
}

fn render_text(input: &Path, result: &AnalysisResult) {
    let report: &Report = &result.report;
    let analysis_state: &str = if report.complete {
        "complete"
    } else {
        "incomplete"
    };
    println!("vulnmatch {}", input.display());
    println!("analysis: {analysis_state}");
    println!(
        "budget: nodes_used={} node_limit_reached={} step_limit_reached={} depth_limit_reached={}",
        result.budget.nodes_used(),
        result.budget.node_limit_reached(),
        result.budget.step_limit_reached(),
        result.budget.depth_limit_reached()
    );
    println!("findings: {}", report.findings.len());
    if report.findings.is_empty() {
        println!("  (none)");
        return;
    }
    println!("tier | score | rule id | sink site | witness path");
    for finding in &report.findings {
        let witness: String = witness_path(finding.witness_path.as_ref());
        println!(
            "tier: {} | {} | rule: {} | sink: {} | path: {}",
            tier_label(finding.tier),
            finding.score,
            finding.rule_id,
            finding.sink_site.id.as_str(),
            witness
        );
    }
}

fn report_to_sarif(input: &Path, report: &Report) -> SarifLog {
    let mut rules: BTreeMap<String, ReportingDescriptor> = BTreeMap::new();
    let mut results: Vec<SarifResult> = Vec::with_capacity(report.findings.len());
    let artifact_uri: String = artifact_uri(input);
    for finding in &report.findings {
        rules
            .entry(finding.rule_id.clone())
            .or_insert_with(|| ReportingDescriptor {
                id: finding.rule_id.clone(),
                name: Some(finding.evidence.cwe.clone()),
                short_description: Some(MultiformatMessageString {
                    text: format!("{} vulnerability rule", finding.evidence.cwe),
                }),
            });
        results.push(SarifResult {
            rule_id: finding.rule_id.clone(),
            level: sarif_level(finding.evidence.severity),
            message: Message {
                text: finding_message(finding, report.complete),
            },
            locations: vec![Location {
                physical_location: PhysicalLocation {
                    artifact_location: ArtifactLocation {
                        uri: artifact_uri.clone(),
                    },
                    region: None,
                },
            }],
        });
    }
    if !report.complete {
        rules.insert(
            INCOMPLETE_ANALYSIS_RULE_ID.to_owned(),
            ReportingDescriptor {
                id: INCOMPLETE_ANALYSIS_RULE_ID.to_owned(),
                name: Some("analysis incomplete".to_owned()),
                short_description: Some(MultiformatMessageString {
                    text: "vulnmatch analysis did not establish complete coverage".to_owned(),
                }),
            },
        );
        results.push(SarifResult {
            rule_id: INCOMPLETE_ANALYSIS_RULE_ID.to_owned(),
            level: SarifLevel::Note,
            message: Message {
                text: "vulnmatch analysis incomplete".to_owned(),
            },
            locations: vec![Location {
                physical_location: PhysicalLocation {
                    artifact_location: ArtifactLocation { uri: artifact_uri },
                    region: None,
                },
            }],
        });
    }
    SarifLog::new(Driver::disrobe(rules.into_values().collect()), results)
}

fn finding_message(finding: &Finding, report_complete: bool) -> String {
    let witness: String = witness_path(finding.witness_path.as_ref());
    let analysis_state: &str = if report_complete {
        "complete"
    } else {
        "incomplete"
    };
    format!(
        "tier={} score={} sink={} witness={} analysis={analysis_state}",
        tier_label(finding.tier),
        finding.score,
        finding.sink_site.id.as_str(),
        witness
    )
}

fn witness_path(path: Option<&PathWitness>) -> String {
    let Some(path) = path else {
        return "(none)".to_owned();
    };
    let functions: Vec<&str> = path.functions.iter().map(FunctionId::as_str).collect();
    functions.join(" -> ")
}

fn artifact_uri(input: &Path) -> String {
    let path: String = input.display().to_string().replace('\\', "/");
    let encoded: String = percent_encode(&path);
    if path.starts_with('/') {
        return format!("file://{encoded}");
    }
    if path
        .as_bytes()
        .get(1)
        .is_some_and(|byte: &u8| *byte == b':')
    {
        return format!("file:///{encoded}");
    }
    encoded
}

fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut encoded: String = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'.' | b'-' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

const fn tier_label(tier: FindingTier) -> &'static str {
    match tier {
        FindingTier::Unknown => "unknown",
        FindingTier::Present => "present",
        FindingTier::ReachabilityUnknown => "reachability-unknown",
        FindingTier::Reachable => "reachable",
        FindingTier::Confirmed => "confirmed",
    }
}

const fn sarif_level(severity: Severity) -> SarifLevel {
    match severity {
        Severity::Low => SarifLevel::Note,
        Severity::Medium => SarifLevel::Warning,
        Severity::High | Severity::Critical => SarifLevel::Error,
    }
}
