use std::collections::BTreeMap;
use std::path::PathBuf;

use disrobe_core::anti_analysis::{self, AntiAnalysisFinding, AntiAnalysisReport, DefeatStatus};
use disrobe_core::behavior::{self, BehaviorReport};
use disrobe_nir::{EffectContext, EffectRow, EffectTable, HardEffect, NirModule};
use serde::Serialize;

use crate::cli::output::{self, OutputFormat};

const MAX_EVIDENCE_SHOWN: usize = 6;

#[derive(Debug, Serialize)]
struct BehaviorWithAntiAnalysis<'a> {
    #[serde(flatten)]
    behavior: &'a BehaviorReport,
    anti_analysis: &'a AntiAnalysisReport,
}

#[derive(Debug, Serialize)]
struct EffectSummary {
    functions: usize,
    instructions: usize,
    effect_free: usize,
    unknown: usize,
    effects: BTreeMap<&'static str, usize>,
    provenance: BTreeMap<&'static str, usize>,
}

#[derive(Debug, Serialize)]
struct BehaviorWithEffects<'a> {
    #[serde(flatten)]
    behavior: &'a BehaviorReport,
    anti_analysis: &'a AntiAnalysisReport,
    effects: EffectSummary,
}

fn summarize_effects(table: &EffectTable) -> EffectSummary {
    let mut effects: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut provenance: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut effect_free: usize = 0;
    let mut unknown: usize = 0;
    for row in table.rows() {
        let row: EffectRow = *row;
        if row.is_unknown() {
            unknown = unknown.saturating_add(1);
        }
        if row.is_effect_free() {
            effect_free = effect_free.saturating_add(1);
        }
        for effect in row.effects().iter() {
            let effect: HardEffect = effect;
            let seen: &mut usize = effects.entry(effect.label()).or_default();
            *seen = seen.saturating_add(1);
            if let Some(source) = row.provenance_of(effect) {
                let counted: &mut usize = provenance.entry(source.label()).or_default();
                *counted = counted.saturating_add(1);
            }
        }
    }
    EffectSummary {
        functions: table.function_count(),
        instructions: table.len(),
        effect_free,
        unknown,
        effects,
        provenance,
    }
}

fn render_effects(summary: &EffectSummary) {
    println!();
    println!(
        "effects over {} instruction(s) in {} function(s)",
        summary.instructions, summary.functions
    );
    println!(
        "  {} carry no hard effect, {} are not modelled",
        summary.effect_free, summary.unknown
    );
    if summary.effects.is_empty() {
        println!("  no hard effect is reported for this input");
        return;
    }
    for (effect, count) in &summary.effects {
        println!("  {effect:<22} {count}");
    }
    println!("evidence for those effects");
    for (source, count) in &summary.provenance {
        println!("  {source:<22} {count}");
    }
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
    for line in anti_analysis_lines(anti) {
        println!("{line}");
    }
}

fn anti_analysis_lines(anti: &AntiAnalysisReport) -> Vec<String> {
    let detected: Vec<&AntiAnalysisFinding> = anti
        .findings
        .iter()
        .filter(|f: &&AntiAnalysisFinding| f.detected)
        .collect();
    let informational: Vec<&AntiAnalysisFinding> = anti
        .findings
        .iter()
        .filter(|f: &&AntiAnalysisFinding| !f.detected)
        .collect();
    if detected.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "\nanti-analysis ({} technique(s), {} overcome):",
        detected.len(),
        anti.overcome_count()
    ));
    for finding in &detected {
        push_anti_analysis_finding_lines(&mut lines, finding);
    }
    for finding in &informational {
        lines.push(format!(
            "  anti-analysis [informational]: [{}] {} -> weak signal surfaced for triage",
            finding.confidence.label(),
            finding.technique.label()
        ));
        push_anti_analysis_evidence_lines(&mut lines, finding);
    }
    lines
}

fn push_anti_analysis_finding_lines(lines: &mut Vec<String>, finding: &AntiAnalysisFinding) {
    let confidence: &str = finding.confidence.label();
    match &finding.defeated_by {
        DefeatStatus::OvercomeBy { mechanism } => {
            lines.push(format!(
                "  anti-analysis: [{confidence}] {} -> overcome via {}",
                finding.technique.label(),
                mechanism.label()
            ));
        }
        DefeatStatus::DetectedNotDefeated { reason } => {
            lines.push(format!(
                "  anti-analysis: [{confidence}] {} -> detected, not defeated: {}",
                finding.technique.label(),
                reason
            ));
        }
    }
    push_anti_analysis_evidence_lines(lines, finding);
}

fn push_anti_analysis_evidence_lines(lines: &mut Vec<String>, finding: &AntiAnalysisFinding) {
    for ev in finding.evidence.iter().take(MAX_EVIDENCE_SHOWN) {
        lines.push(format!("    - {}", trim_signal(ev)));
    }
    if finding.evidence.len() > MAX_EVIDENCE_SHOWN {
        lines.push(format!(
            "    ... {} more signal(s)",
            finding.evidence.len() - MAX_EVIDENCE_SHOWN
        ));
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

pub(crate) fn run(path: PathBuf, fmt: OutputFormat, effects: bool) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-BEH-0050: cannot read target: {e}"))?;
    let uri: String = path.display().to_string();
    let imports: Vec<String> = native_import_tokens(&bytes);
    let report: BehaviorReport = behavior::analyze_with_uri(&bytes, &imports, Some(&uri));
    let anti: AntiAnalysisReport = anti_analysis::scan(&bytes, Some(&uri));
    if !effects {
        let combined: BehaviorWithAntiAnalysis<'_> = BehaviorWithAntiAnalysis {
            behavior: &report,
            anti_analysis: &anti,
        };
        return output::emit(fmt, &combined, || {
            render_text(&report);
            render_anti_analysis(&anti);
        });
    }
    let module: NirModule = crate::cli::nir_source::lift_module_from_bytes(&path, &bytes)?;
    let table: EffectTable =
        EffectTable::for_module(&module, &EffectContext::new()).map_err(|e| {
            miette::miette!("DR-BEH-0051: cannot derive an effect table for this input: {e}")
        })?;
    let combined: BehaviorWithEffects<'_> = BehaviorWithEffects {
        behavior: &report,
        anti_analysis: &anti,
        effects: summarize_effects(&table),
    };
    output::emit(fmt, &combined, || {
        render_text(&report);
        render_anti_analysis(&anti);
        render_effects(&combined.effects);
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use disrobe_core::anti_analysis::{
        Confidence, FindingSeverity, Mechanism, TargetFamily, Technique,
    };
    use disrobe_core::behavior::{CategoryFinding, Evidence};

    fn finding(detected: bool, defeated_by: DefeatStatus) -> AntiAnalysisFinding {
        AntiAnalysisFinding {
            technique: Technique::AntiDebug,
            detected,
            severity: if detected {
                FindingSeverity::Detected
            } else {
                FindingSeverity::Informational
            },
            confidence: Confidence::Medium,
            defeated_by,
            evidence: vec!["IsDebuggerPresent".to_owned()],
        }
    }

    #[test]
    fn detected_and_informational_findings_render_distinct_phrasing() {
        let report: AntiAnalysisReport = AntiAnalysisReport {
            schema: "test".to_owned(),
            uri: None,
            byte_len: 0,
            target_family: TargetFamily::Pe,
            findings: vec![
                finding(
                    true,
                    DefeatStatus::DetectedNotDefeated {
                        reason: "no corroborating signal".to_owned(),
                    },
                ),
                finding(
                    false,
                    DefeatStatus::DetectedNotDefeated {
                        reason: "no corroborating signal".to_owned(),
                    },
                ),
            ],
        };
        let lines: Vec<String> = anti_analysis_lines(&report);
        let detected_count: usize = lines
            .iter()
            .filter(|l: &&String| l.contains("detected, not defeated"))
            .count();
        assert_eq!(detected_count, 1, "{lines:?}");
        let informational_lines: Vec<&String> = lines
            .iter()
            .filter(|l: &&String| l.contains("[informational]"))
            .collect();
        assert_eq!(informational_lines.len(), 1, "{lines:?}");
        assert!(
            !informational_lines[0].contains("detected, not defeated"),
            "{lines:?}"
        );
    }

    #[test]
    fn zero_detected_findings_render_nothing() {
        let report: AntiAnalysisReport = AntiAnalysisReport {
            schema: "test".to_owned(),
            uri: None,
            byte_len: 0,
            target_family: TargetFamily::Pe,
            findings: vec![finding(
                false,
                DefeatStatus::DetectedNotDefeated {
                    reason: "no corroborating signal".to_owned(),
                },
            )],
        };
        assert!(anti_analysis_lines(&report).is_empty());
    }

    #[test]
    fn a_detected_overcome_finding_still_renders_as_before() {
        let report: AntiAnalysisReport = AntiAnalysisReport {
            schema: "test".to_owned(),
            uri: None,
            byte_len: 0,
            target_family: TargetFamily::Pe,
            findings: vec![finding(
                true,
                DefeatStatus::OvercomeBy {
                    mechanism: Mechanism::Desync,
                },
            )],
        };
        let lines: Vec<String> = anti_analysis_lines(&report);
        assert!(
            lines.iter().any(|l: &String| l.contains("overcome via")),
            "{lines:?}"
        );
    }

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
