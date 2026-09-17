use std::path::PathBuf;

use disrobe_binfmt::{ByteCoverage, CoverageRegion, RegionClass, file_byte_coverage};
use disrobe_pass_native::{FileIdReport, identify_file};
use serde::Serialize;

use crate::cli::output::{self, OutputFormat};

#[derive(Serialize)]
struct IdentifyWithCoverage<'a> {
    #[serde(flatten)]
    identity: &'a FileIdReport,
    coverage: ByteCoverage,
}

pub(crate) fn run(path: PathBuf, fmt: OutputFormat, coverage: bool) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-IDENTIFY-0050: cannot read target: {e}"))?;
    let report: FileIdReport = identify_file(&bytes);
    if !coverage {
        return output::emit(fmt, &report, || render_text(&report));
    }
    let mapped: ByteCoverage = file_byte_coverage(&bytes).map_err(|e| {
        miette::miette!("DR-IDENTIFY-0051: cannot account for the bytes of this input: {e}")
    })?;
    let combined: IdentifyWithCoverage<'_> = IdentifyWithCoverage {
        identity: &report,
        coverage: mapped,
    };
    output::emit(fmt, &combined, || {
        render_text(&report);
        render_coverage(&combined.coverage);
    })
}

fn render_coverage(coverage: &ByteCoverage) {
    println!();
    println!(
        "bytes accounted for: {} of {} ({:.2}%)",
        coverage.claimed_bytes,
        coverage.file_len,
        coverage.coverage_ratio * 100.0
    );
    println!(
        "unclaimed {}, slack {}, missing {}",
        coverage.unclaimed_bytes, coverage.slack_bytes, coverage.truncated_bytes
    );
    if coverage.overlap_detected {
        println!(
            "{} region pair(s) claim the same bytes",
            coverage.overlaps.len()
        );
    }
    for claim in &coverage.unbacked {
        println!(
            "  unbacked  {} declares {} bytes that the file does not store",
            claim.claimant, claim.declared_size
        );
    }
    for claim in &coverage.truncated {
        println!(
            "  truncated {} declares bytes to {} but the file ends at {}, missing {}",
            claim.claimant, claim.declared_end, claim.present_end, claim.missing_bytes
        );
    }
    for region in unclaimed_regions(coverage) {
        println!(
            "  unclaimed 0x{:x}..0x{:x} ({} bytes)",
            region.start,
            region.end,
            region.len()
        );
    }
}

fn unclaimed_regions(coverage: &ByteCoverage) -> Vec<&CoverageRegion> {
    coverage
        .regions
        .iter()
        .filter(|region: &&CoverageRegion| region.class == RegionClass::Unclaimed)
        .collect()
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
