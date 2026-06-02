use std::path::PathBuf;

use disrobe_core::{SecretScanReport, scan_report};

use crate::cli::output::{self, OutputFormat};

pub(crate) fn run(path: PathBuf, fmt: OutputFormat) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-SCAN-0050: cannot read target: {e}"))?;
    let uri: String = path.display().to_string();
    let report: SecretScanReport = scan_report(&bytes, Some(&uri));
    output::emit(fmt, &report, || {
        if report.findings.is_empty() {
            println!("no secrets detected");
        } else {
            for f in &report.findings {
                println!(
                    "{}\t{}\t{}\t@{}",
                    f.level, f.code, f.redacted_preview, f.offset
                );
            }
        }
    })
}
