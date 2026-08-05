use std::path::Path;
use std::path::PathBuf;

use disrobe_llm_metadata::{MetadataSelection, PipelineStep};
use disrobe_nir::NirModule;
use disrobe_taint::{TaintConfig, TaintFinding, TaintReport, TaintStep};
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

#[derive(Debug, Serialize)]
struct TaintOutput<'a> {
    input: String,
    source_lang: &'a str,
    sources: Vec<&'a str>,
    sinks: Vec<&'a str>,
    finding_count: usize,
    findings: &'a [TaintFinding],
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
    let report: TaintReport = disrobe_taint::analyze(&module, &config);
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
