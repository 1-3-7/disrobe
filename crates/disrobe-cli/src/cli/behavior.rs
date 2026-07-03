use std::path::PathBuf;

use disrobe_core::anti_analysis::{self, AntiAnalysisReport, DefeatStatus};
use disrobe_core::behavior::{self, BehaviorReport};
use serde::Serialize;

use crate::cli::output::{self, OutputFormat};

const MAX_EVIDENCE_SHOWN: usize = 6;

#[derive(Debug, Serialize)]
struct BehaviorWithAntiAnalysis<'a> {
    #[serde(flatten)]
    behavior: &'a BehaviorReport,
    anti_analysis: &'a AntiAnalysisReport,
}

fn native_import_tokens(bytes: &[u8]) -> Vec<String> {
    match disrobe_binfmt::native::parse_native(bytes) {
        Ok(native) => {
            let mut tokens: Vec<String> = Vec::with_capacity(native.imports.len());
            for i in &native.imports {
                tokens.push(format!("{}!{}", i.library, i.name));
                tokens.push(i.name.clone());
            }
            for s in &native.symbols {
                tokens.push(s.name.clone());
            }
            tokens
        }
        Err(_) => Vec::new(),
    }
}

fn render_text(report: &BehaviorReport) {
    if report.categories.is_empty() {
        println!("no notable behaviors detected");
        return;
    }
    for finding in &report.categories {
        let attack: String = if finding.attack_ids.is_empty() {
            String::new()
        } else {
            format!("  [{}]", finding.attack_ids.join(", "))
        };
        println!(
            "{}  ({}){attack}",
            finding.category.label(),
            finding.description
        );
        for ev in finding.evidence.iter().take(MAX_EVIDENCE_SHOWN) {
            let id: String = ev
                .attack_id
                .map_or_else(String::new, |a: &str| format!(" -> {a}"));
            println!("    - {} [{}]{id}", trim_signal(&ev.signal), ev.source);
        }
        if finding.evidence.len() > MAX_EVIDENCE_SHOWN {
            println!(
                "    ... {} more signal(s)",
                finding.evidence.len() - MAX_EVIDENCE_SHOWN
            );
        }
    }
    if !report.attack_ids.is_empty() {
        println!("\nATT&CK: {}", report.attack_ids.join(", "));
    }
}

fn render_anti_analysis(anti: &AntiAnalysisReport) {
    if !anti.any_detected() {
        return;
    }
    println!(
        "\nanti-analysis ({} technique(s), {} overcome):",
        anti.findings.len(),
        anti.overcome_count()
    );
    for finding in &anti.findings {
        let confidence: &str = finding.confidence.label();
        match &finding.defeated_by {
            DefeatStatus::OvercomeBy { mechanism } => {
                println!(
                    "  anti-analysis: [{confidence}] {} -> overcome via {}",
                    finding.technique.label(),
                    mechanism.label()
                );
            }
            DefeatStatus::DetectedNotDefeated { reason } => {
                println!(
                    "  anti-analysis: [{confidence}] {} -> detected, not defeated: {}",
                    finding.technique.label(),
                    reason
                );
            }
        }
        for ev in finding.evidence.iter().take(MAX_EVIDENCE_SHOWN) {
            println!("    - {}", trim_signal(ev));
        }
        if finding.evidence.len() > MAX_EVIDENCE_SHOWN {
            println!(
                "    ... {} more signal(s)",
                finding.evidence.len() - MAX_EVIDENCE_SHOWN
            );
        }
    }
}

fn trim_signal(signal: &str) -> String {
    const MAX: usize = 80;
    if signal.chars().count() <= MAX {
        signal.replace(['\n', '\r', '\t'], " ")
    } else {
        let head: String = signal.chars().take(MAX).collect();
        format!("{}\u{2026}", head.replace(['\n', '\r', '\t'], " "))
    }
}

pub(crate) fn run(path: PathBuf, fmt: OutputFormat) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-BEH-0050: cannot read target: {e}"))?;
    let uri: String = path.display().to_string();
    let imports: Vec<String> = native_import_tokens(&bytes);
    let report: BehaviorReport = behavior::analyze_with_uri(&bytes, &imports, Some(&uri));
    let anti: AntiAnalysisReport = anti_analysis::scan(&bytes, Some(&uri));
    let combined: BehaviorWithAntiAnalysis<'_> = BehaviorWithAntiAnalysis {
        behavior: &report,
        anti_analysis: &anti,
    };
    output::emit(fmt, &combined, || {
        render_text(&report);
        render_anti_analysis(&anti);
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use disrobe_core::behavior::{CategoryFinding, Evidence};

    #[test]
    fn trim_signal_caps_long_input() {
        let long: String = "a".repeat(200);
        let trimmed: String = trim_signal(&long);
        assert!(trimmed.chars().count() <= 81, "{}", trimmed.len());
        assert!(trimmed.ends_with('\u{2026}'));
    }

    #[test]
    fn text_render_lists_categories_and_attack() {
        let report: BehaviorReport = behavior::analyze(
            b"connect to http://c2.example.com/",
            &["ws2_32.dll!connect".to_owned()],
        );
        let net: Option<&CategoryFinding> = report
            .categories
            .iter()
            .find(|c: &&CategoryFinding| c.category == disrobe_core::behavior::Category::Network);
        assert!(net.is_some(), "{report:?}");
        let ev: &Evidence = &net.expect("net").evidence[0];
        assert!(!ev.signal.is_empty());
    }
}
