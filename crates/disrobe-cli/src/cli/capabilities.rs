use std::path::{Path, PathBuf};

use disrobe_capabilities::{CapabilitiesReport, CapabilityMatch, Evidence};
use disrobe_ir::Envelope;
use disrobe_ir::payload::DisasmPayload;
use disrobe_pass_native::build_disasm_payload;
use disrobe_query::Module;

use crate::cli::output::{self, OutputFormat};
use crate::cli::progress_ui::StageSpinner;

pub(crate) fn run(input: PathBuf, fmt: OutputFormat) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0840: cannot read {}: {e}", input.display()))?;
    let uri: String = input.display().to_string();
    let report: CapabilitiesReport = build_report(&bytes, &uri, &input)?;
    output::emit(fmt, &report, || render_text(&report))
}

fn build_report(bytes: &[u8], uri: &str, input: &Path) -> miette::Result<CapabilitiesReport> {
    if let Ok(env) = Envelope::decode(bytes) {
        let module: Module = disrobe_query::module_from_envelope(&env).map_err(|e| {
            miette::miette!(
                "DR-CLI-0841: {} is a .dr envelope but not a Disasm or Mir rung the capabilities engine can read: {e}",
                input.display()
            )
        })?;
        return Ok(disrobe_capabilities::analyze_module(
            &module,
            bytes,
            Some(uri),
        ));
    }
    let spinner: StageSpinner = StageSpinner::start(uri, "disassembling for capabilities");
    let payload: DisasmPayload = build_disasm_payload(bytes).map_err(|e| {
        miette::miette!(
            "DR-CLI-0842: {} is neither a Disasm- or Mir-rung .dr envelope nor a disassemblable native binary: {e}",
            input.display()
        )
    })?;
    spinner.finish(&format!("{} bytes analyzed", bytes.len()));
    let module: Module = Module::from_disasm(&payload);
    Ok(disrobe_capabilities::analyze_module(
        &module,
        bytes,
        Some(uri),
    ))
}

fn render_text(report: &CapabilitiesReport) {
    println!(
        "capabilities: {} rule(s) matched over {} bytes",
        report.matched_rules, report.byte_len
    );
    if !report.attack.is_empty() {
        println!("  ATT&CK: {}", report.attack.join(", "));
    }
    if !report.mbc.is_empty() {
        println!("  MBC:    {}", report.mbc.join(", "));
    }
    if report.capabilities.is_empty() {
        println!("  (no capabilities matched)");
        return;
    }
    println!();
    for m in &report.capabilities {
        render_match(m);
    }
}

fn render_match(m: &CapabilityMatch) {
    let location: String = m.function.as_ref().map_or_else(
        || format!("{:#018x}", m.address),
        |name: &String| {
            let func_addr: u64 = m.function_address.unwrap_or(m.address);
            format!("{:#018x} {name} ({func_addr:#x})", m.address)
        },
    );
    let tags: String = attack_mbc_suffix(m);
    println!("  {location}");
    println!(
        "    {} [{}] {}: {}{tags}",
        m.rule,
        m.scope.label(),
        m.namespace,
        m.description
    );
    for e in &m.evidence {
        render_evidence(e);
    }
}

fn attack_mbc_suffix(m: &CapabilityMatch) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !m.attack.is_empty() {
        parts.push(format!("ATT&CK {}", m.attack.join("/")));
    }
    if !m.mbc.is_empty() {
        parts.push(format!("MBC {}", m.mbc.join("/")));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("  [{}]", parts.join(", "))
    }
}

fn render_evidence(e: &Evidence) {
    println!("      {:#018x}  {}", e.address, e.feature);
}
