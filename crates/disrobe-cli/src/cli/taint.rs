use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;

use disrobe_llm_metadata::{MetadataSelection, PipelineStep};
use disrobe_nir::{NirModule, NirOp};
use disrobe_query::{
    CallOutcome, FunctionIdentity, Module, NavigationCall, NavigationLimitError, NavigationLimits,
};
use disrobe_taint::{
    CallEdge, CallEdgeEvidence, TaintConfig, TaintFinding, TaintReport, TaintStep,
};
use serde::Serialize;
use serde_json::Value as Json;

use crate::cli::ir_metadata;
use crate::cli::llm::{self as llm_cli, LlmFlags};
use crate::cli::nir_source::lift_module_from_bytes;
use crate::cli::output::{self, OutputFormat};

const DEFAULT_SOURCES: &[&str] = &[
    "recv",
    "recvfrom",
    "read",
    "fread",
    "fgets",
    "gets",
    "accept",
    "socket",
    "input",
    "getenv",
    "ReadFile",
    "InternetReadFile",
    "os.read",
    "sys.stdin.read",
    "socket.socket",
    "socket.recv",
    "sock.recv",
    "request.args.get",
    "request.form.get",
    "request.get_data",
];

const DEFAULT_SINKS: &[&str] = &[
    "system",
    "popen",
    "exec",
    "execl",
    "execv",
    "execve",
    "execvp",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "CreateProcessA",
    "CreateProcessW",
    "eval",
    "write",
    "fwrite",
    "send",
    "sendto",
    "connect",
    "WriteFile",
    "os.system",
    "os.popen",
    "os.exec",
    "os.execv",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_output",
];

const MAX_NAVIGATION_FUNCTIONS: usize = 8_192;
const MAX_NAVIGATION_INSTRUCTIONS: usize = 262_144;
const MAX_NAVIGATION_CALLS: usize = 32_768;
const MAX_NAVIGATION_CANDIDATE_RECORDS: usize = 65_536;
const MAX_NAVIGATION_RETAINED_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Serialize)]
struct TaintOutput<'a> {
    input: String,
    source_lang: &'a str,
    sources: Vec<&'a str>,
    sinks: Vec<&'a str>,
    finding_count: usize,
    findings: &'a [TaintFinding],
    call_edges: &'a [CallEdge],
    #[serde(skip_serializing_if = "Option::is_none")]
    llm_bundle: Option<String>,
}

pub(crate) fn run(
    input: PathBuf,
    sources: Vec<String>,
    sinks: Vec<String>,
    fmt: OutputFormat,
    llm_flags: &LlmFlags,
) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0850: cannot read {}: {e}", input.display()))?;
    let module: NirModule = lift_module_from_bytes(&input, &bytes)?;
    let config: TaintConfig = build_config(&sources, &sinks);
    let call_edges: Vec<CallEdge> = navigation_call_edges(&module)?;
    let report: TaintReport = disrobe_taint::analyze_with_call_edges(&module, &config, &call_edges);
    let lang: &str = module.lang.label();
    let resolved_sources: Vec<&str> = config.sources().collect();
    let resolved_sinks: Vec<&str> = config.sinks().collect();
    let llm_out: Option<llm_cli::LlmOutputs> =
        maybe_emit_llm_taint(llm_flags, &input, &bytes, &module)?;
    let payload: TaintOutput<'_> = TaintOutput {
        input: input.display().to_string(),
        source_lang: lang,
        sources: resolved_sources,
        sinks: resolved_sinks,
        finding_count: report.findings().len(),
        findings: report.findings(),
        call_edges: report.call_edges(),
        llm_bundle: llm_out
            .as_ref()
            .map(|o: &llm_cli::LlmOutputs| o.bundle.display().to_string()),
    };
    output::emit(fmt, &payload, || {
        render_text(&input, lang, &config, &report);
        if let Some(o) = llm_out.as_ref() {
            println!("llm bundle: {}", o.bundle.display());
        }
    })
}

fn navigation_call_edges(module: &NirModule) -> miette::Result<Vec<CallEdge>> {
    let query: Module = Module::from_nir(module);
    let extern_sites: BTreeSet<u64> = module
        .functions
        .iter()
        .flat_map(|function| function.instructions.iter())
        .filter(|instruction| matches!(instruction.op, NirOp::ExternCall { .. }))
        .map(|instruction| instruction.address)
        .collect();
    let calls: Vec<NavigationCall> = query
        .navigation_calls(NavigationLimits {
            functions: MAX_NAVIGATION_FUNCTIONS,
            instructions: MAX_NAVIGATION_INSTRUCTIONS,
            calls: MAX_NAVIGATION_CALLS,
            candidate_records: MAX_NAVIGATION_CANDIDATE_RECORDS,
            retained_bytes: MAX_NAVIGATION_RETAINED_BYTES,
        })
        .map_err(|error: NavigationLimitError| {
            miette::miette!("DR-CLI-0871: taint call-edge analysis: {error}")
        })?;
    calls
        .iter()
        .filter(|call: &&NavigationCall| !extern_sites.contains(&call.call_site))
        .map(call_edge_from_navigation)
        .collect()
}

fn call_edge_from_navigation(call: &NavigationCall) -> miette::Result<CallEdge> {
    let edge: CallEdge = match call.outcome.as_ref() {
        CallOutcome::FunctionStart { address, .. } => CallEdge::definite(
            call.call_site,
            *address,
            CallEdgeEvidence::NavigationFunctionStart,
        ),
        CallOutcome::FunctionInterior {
            function_address,
            target_address,
            ..
        } => CallEdge::definite(
            call.call_site,
            *function_address,
            CallEdgeEvidence::NavigationFunctionInterior {
                target_address: *target_address,
            },
        ),
        CallOutcome::AmbiguousFunction { candidates, .. } => CallEdge::finite_set(
            call.call_site,
            candidates
                .iter()
                .map(|candidate: &FunctionIdentity| candidate.address),
            CallEdgeEvidence::NavigationAmbiguousFunction,
        )
        .map_err(|_: disrobe_taint::CallEdgeBuildError| {
            miette::miette!(
                "DR-CLI-0872: navigation returned an empty ambiguous call target set at {:#x}",
                call.call_site
            )
        })?,
        CallOutcome::Symbol { address, .. } => CallEdge::definite(
            call.call_site,
            *address,
            CallEdgeEvidence::NavigationSymbol {
                target_address: *address,
            },
        ),
        CallOutcome::Unresolved { address } => CallEdge::unresolved(
            call.call_site,
            CallEdgeEvidence::NavigationUnresolved {
                target_address: *address,
            },
        ),
        CallOutcome::Indirect => {
            CallEdge::unresolved(call.call_site, CallEdgeEvidence::NavigationIndirect)
        }
    };
    Ok(edge)
}

fn maybe_emit_llm_taint(
    llm_flags: &LlmFlags,
    input: &Path,
    bytes: &[u8],
    module: &NirModule,
) -> miette::Result<Option<llm_cli::LlmOutputs>> {
    let Some(selection): Option<MetadataSelection> = llm_flags.to_selection()? else {
        return Ok(None);
    };
    let Some(pass): Option<(PipelineStep, Json)> = ir_metadata::summarize(&selection, module)
    else {
        return Err(miette::miette!(
            "DR-CLI-0844: the requested metadata selects no category `taint` can produce; it contributes cfg and dfg, so pass --cfg, --dfg, --metadata-pack-2, --metadata-pack-3 or --llm"
        ));
    };
    let primary_output: PathBuf = default_bundle_anchor(input);
    let outputs: llm_cli::LlmOutputs = llm_cli::write_llm_bundle(
        llm_flags,
        &selection,
        input,
        bytes,
        &primary_output,
        vec![pass],
    )?;
    Ok(Some(outputs))
}

fn default_bundle_anchor(input: &Path) -> PathBuf {
    let stem: &str = input
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("taint");
    PathBuf::from("./out").join(stem)
}

fn build_config(sources: &[String], sinks: &[String]) -> TaintConfig {
    let mut config: TaintConfig = TaintConfig::new();
    if sources.is_empty() {
        for source in DEFAULT_SOURCES {
            config = config.with_source(*source);
        }
    } else {
        for source in sources {
            config = config.with_source(source.clone());
        }
    }
    if sinks.is_empty() {
        for sink in DEFAULT_SINKS {
            config = config.with_sink(*sink);
        }
    } else {
        for sink in sinks {
            config = config.with_sink(sink.clone());
        }
    }
    config
}

fn render_text(input: &Path, lang: &str, config: &TaintConfig, report: &TaintReport) {
    let findings: &[TaintFinding] = report.findings();
    println!("taint {} ({lang})", input.display());
    println!(
        "sources: {}",
        join_symbols(config.sources().collect::<Vec<&str>>())
    );
    println!(
        "sinks:   {}",
        join_symbols(config.sinks().collect::<Vec<&str>>())
    );
    println!("flows: {}", findings.len());
    if findings.is_empty() {
        println!("  (no source reaches any sink)");
        return;
    }
    for finding in findings {
        println!();
        println!(
            "  {} -> {}  in {} ({:#x})",
            finding.source_symbol, finding.sink_symbol, finding.function, finding.function_address
        );
        println!(
            "    source {:#018x}  sink {:#018x}",
            finding.source_site, finding.sink_site
        );
        for step in &finding.path {
            render_step(step);
        }
    }
}

fn render_step(step: &TaintStep) {
    println!(
        "      {:#018x}  {:<10} {}",
        step.address, step.kind, step.symbol
    );
}

fn join_symbols(symbols: Vec<&str>) -> String {
    if symbols.is_empty() {
        return "(none)".to_owned();
    }
    symbols.join(", ")
}
