use std::path::Path;
use std::path::PathBuf;

use disrobe_ir::Envelope;
use disrobe_ir::payload::DisasmPayload;
use disrobe_nir::NirModule;
use disrobe_pass_native::build_disasm_payload;
use disrobe_query::disasm_to_nir;
use disrobe_taint::{TaintConfig, TaintFinding, TaintReport, TaintStep};
use serde::Serialize;

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
}

pub(crate) fn run(
    input: PathBuf,
    sources: Vec<String>,
    sinks: Vec<String>,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let module: NirModule = lift_module(&input)?;
    let config: TaintConfig = build_config(&sources, &sinks);
    let report: TaintReport = disrobe_taint::analyze(&module, &config);
    let lang: &str = module.lang.label();
    let resolved_sources: Vec<&str> = config.sources().collect();
    let resolved_sinks: Vec<&str> = config.sinks().collect();
    let payload: TaintOutput<'_> = TaintOutput {
        input: input.display().to_string(),
        source_lang: lang,
        sources: resolved_sources,
        sinks: resolved_sinks,
        finding_count: report.findings().len(),
        findings: report.findings(),
    };
    output::emit(fmt, &payload, || {
        render_text(&input, lang, &config, &report);
    })
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

fn lift_module(input: &Path) -> miette::Result<NirModule> {
    let bytes: Vec<u8> = std::fs::read(input)
        .map_err(|e| miette::miette!("DR-CLI-0850: cannot read {}: {e}", input.display()))?;
    if let Ok(env) = Envelope::decode(&bytes) {
        return module_from_envelope(&env, input);
    }
    if let Some(module) = lift_front_end(&bytes) {
        return Ok(module);
    }
    let payload: DisasmPayload = build_disasm_payload(&bytes).map_err(|e| {
        miette::miette!(
            "DR-CLI-0851: {} is not a .dr envelope, a lift-supported source format (wasm/jvm/dex/pyc), nor a disassemblable native binary: {e}",
            input.display()
        )
    })?;
    Ok(disasm_to_nir(&payload))
}

fn module_from_envelope(env: &Envelope, input: &Path) -> miette::Result<NirModule> {
    use disrobe_core::Rung;
    use disrobe_ir::payload::decode_disasm;
    use disrobe_nir::decode_nir;
    match env.rung {
        Rung::Mir => decode_nir(&env.hot).map_err(|e| {
            miette::miette!(
                "DR-CLI-0852: {} is a Mir-rung .dr envelope but the NIR payload did not decode: {e}",
                input.display()
            )
        }),
        Rung::Disasm => {
            let payload: DisasmPayload = decode_disasm(&env.hot).map_err(|e| {
                miette::miette!(
                    "DR-CLI-0853: {} is a Disasm-rung .dr envelope but the payload did not decode: {e}",
                    input.display()
                )
            })?;
            Ok(disasm_to_nir(&payload))
        }
        other => Err(miette::miette!(
            "DR-CLI-0854: {} is a {other:?}-rung .dr envelope; taint needs a Disasm- or Mir-rung envelope or a source format the lifters accept",
            input.display()
        )),
    }
}

#[cfg(any(
    feature = "as3",
    feature = "beam",
    feature = "dotnet",
    feature = "jvm",
    feature = "lua",
    feature = "ruby",
    feature = "wasm"
))]
fn lift_front_end(bytes: &[u8]) -> Option<NirModule> {
    #[cfg(feature = "wasm")]
    if bytes.len() >= 4 && bytes[..4] == [0x00, 0x61, 0x73, 0x6d] {
        return disrobe_nir_lift::lift_wasm_module(bytes).ok();
    }
    #[cfg(feature = "jvm")]
    if bytes.len() >= 4 && bytes[..4] == [0xca, 0xfe, 0xba, 0xbe] {
        return disrobe_nir_lift::lift_classfile(bytes).ok();
    }
    #[cfg(feature = "jvm")]
    if bytes.len() >= 8 && bytes[..4] == [b'd', b'e', b'x', b'\n'] && bytes[7] == 0 {
        return disrobe_nir_lift::lift_dex(bytes).ok();
    }
    #[cfg(feature = "dotnet")]
    if bytes.len() >= 2 && bytes[..2] == [b'M', b'Z'] && is_managed_pe(bytes) {
        return disrobe_nir_lift::lift_dotnet_pe(bytes).ok();
    }
    #[cfg(feature = "as3")]
    if is_swf(bytes) {
        return disrobe_nir_lift::lift_swf_abc(bytes).ok();
    }
    #[cfg(feature = "as3")]
    if is_raw_abc(bytes) {
        return disrobe_nir_lift::lift_abc(bytes).ok();
    }
    #[cfg(feature = "ruby")]
    if bytes.len() >= 4 && bytes[..4] == [b'Y', b'A', b'R', b'B'] {
        return disrobe_nir_lift::lift_ruby_iseq(bytes).ok();
    }
    #[cfg(feature = "lua")]
    if bytes.len() >= 4 && bytes[..4] == [0x1B, b'L', b'u', b'a'] {
        return disrobe_nir_lift::lift_lua_chunk(bytes).ok();
    }
    #[cfg(feature = "beam")]
    if bytes.len() >= 12
        && bytes[..4] == [b'F', b'O', b'R', b'1']
        && bytes[8..12] == [b'B', b'E', b'A', b'M']
    {
        return disrobe_nir_lift::lift_beam_module(bytes).ok();
    }
    None
}

#[cfg(not(any(
    feature = "as3",
    feature = "beam",
    feature = "dotnet",
    feature = "jvm",
    feature = "lua",
    feature = "ruby",
    feature = "wasm"
)))]
const fn lift_front_end(_bytes: &[u8]) -> Option<NirModule> {
    None
}

#[cfg(feature = "as3")]
fn is_swf(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && matches!(&bytes[..3], b"FWS" | b"CWS" | b"ZWS")
}

#[cfg(feature = "as3")]
fn is_raw_abc(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == [0x10, 0x00, 0x2E, 0x00]
}

#[cfg(feature = "dotnet")]
fn is_managed_pe(bytes: &[u8]) -> bool {
    disrobe_pass_dotnet::parse(bytes)
        .ok()
        .and_then(|pe| disrobe_pass_dotnet::parse_clr_header(bytes, &pe).ok())
        .is_some()
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
