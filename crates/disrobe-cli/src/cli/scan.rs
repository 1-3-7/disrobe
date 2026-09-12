use std::path::PathBuf;

use disrobe_core::recon::redact::Redactor;
use disrobe_core::{Confidence, SecretScanReport, scan_report};

use crate::cli::output::{self, OutputFormat};

fn render_text(report: &SecretScanReport) {
    if report.findings.is_empty() {
        println!("no secrets detected");
        return;
    }
    for f in &report.findings {
        let validation: &str = f
            .validation
            .map_or("unvalidated", |c: Confidence| c.label());
        let uri: &str = f.uri.as_deref().unwrap_or("-");
        println!(
            "{}\t{}\t{}\t{}\t{}\t@{}\t{}",
            f.level,
            f.code,
            f.kind.describe(),
            validation,
            uri,
            f.offset,
            f.value
        );
    }
}

pub(crate) fn run(path: PathBuf, fmt: OutputFormat, redact: bool) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-SCAN-0050: cannot read target: {e}"))?;
    let uri: String = path.display().to_string();
    let mut report: SecretScanReport = scan_report(&bytes, Some(&uri));
    if redact {
        Redactor::new().redact_secret_report(&mut report);
    }
    output::emit(fmt, &report, || render_text(&report))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use disrobe_core::Finding;

    use super::*;

    fn aws_akid() -> String {
        format!("{}{}", "AKIA", "3KFTG2KQ4WXYZ7AB")
    }

    #[test]
    fn text_row_carries_kind_validation_uri_and_the_full_value() {
        let key: String = aws_akid();
        let report: SecretScanReport =
            scan_report(format!("key = {key}\n").as_bytes(), Some("keys.txt"));
        let f: &Finding = report
            .findings
            .iter()
            .find(|f: &&Finding| f.code == "DR-SEC-AWS-AKID")
            .expect("the fixture must produce an aws access key finding");
        assert_eq!(f.value, key, "the finding must carry the full match");
        assert!(
            f.preview.len() < key.len(),
            "the compact preview must stay shorter than the value: {}",
            f.preview
        );
        assert_eq!(f.kind.describe(), "AWS access key id");
        assert_eq!(f.uri.as_deref(), Some("keys.txt"));
    }
}
