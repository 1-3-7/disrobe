use std::path::PathBuf;

use disrobe_pass_native::{FileIdReport, identify_file};

use crate::cli::output::{self, OutputFormat};

pub(crate) fn run(path: PathBuf, fmt: OutputFormat) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-IDENTIFY-0050: cannot read target: {e}"))?;
    let report: FileIdReport = identify_file(&bytes);
    output::emit(fmt, &report, || render_text(&report))
}

fn render_text(report: &FileIdReport) {
    print!("format: {}", report.format);
    if report.bits != 0 {
        print!(" ({}-bit)", report.bits);
    }
    if let Some(sub) = report.subsystem.as_deref() {
        print!(" subsystem={sub}");
    }
    println!();
    if report.findings.is_empty() {
        println!("no toolchain, packer, protector, or installer signatures matched");
        return;
    }
    for finding in &report.findings {
        let version: String = finding
            .version
            .as_deref()
            .map(|v: &str| format!(" {v}"))
            .unwrap_or_default();
        println!(
            "{:<10} {}{}  ({}%)  -> {}",
            kind_label(finding.kind),
            finding.name,
            version,
            finding.confidence,
            finding.support.command()
        );
        for ev in &finding.evidence {
            println!("             - [{}] {}", ev.locus, ev.detail);
        }
    }
}

const fn kind_label(kind: disrobe_pass_native::IdentityKind) -> &'static str {
    use disrobe_pass_native::IdentityKind;
    match kind {
        IdentityKind::Compiler => "compiler",
        IdentityKind::Linker => "linker",
        IdentityKind::Packer => "packer",
        IdentityKind::Protector => "protector",
        IdentityKind::Installer => "installer",
        IdentityKind::Library => "library",
        IdentityKind::Sign => "sign",
        IdentityKind::Format => "format",
    }
}
