use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_core::recon::git_history::{self, GitFinding, GitHistoryOptions, GitHistoryReport};
use disrobe_core::recon::redact::Redactor;
use disrobe_core::recon::{
    self, CustomPattern, ReconConfig, ReconFinding, ReconReport, fingerprint,
};

use crate::cli::output::OutputFormat;
use crate::cli::progress_ui::StageSpinner;
use crate::cli::sarif::{
    ArtifactLocation, Driver, Location, Message, PhysicalLocation, Region, ReportingDescriptor,
    SarifLevel, SarifLog, SarifResult,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum FriskFormat {
    #[default]
    Text,
    Json,
    Sarif,
}

fn load_patterns(path: &PathBuf) -> miette::Result<Vec<CustomPattern>> {
    let text: String = std::fs::read_to_string(path)
        .map_err(|e| miette::miette!("DR-FRISK-0060: cannot read pattern file: {e}"))?;
    let mut patterns: Vec<CustomPattern> = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line: &str = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, pattern)): Option<(&str, &str)> = line.split_once('=') else {
            return Err(miette::miette!(
                "DR-FRISK-0061: pattern line {} must be `name=regex`",
                lineno + 1
            ));
        };
        let compiled: CustomPattern = CustomPattern::compile(name.trim(), pattern.trim())
            .map_err(|e| miette::miette!("DR-FRISK-0062: {e}"))?;
        patterns.push(compiled);
    }
    Ok(patterns)
}

fn load_baseline(path: &PathBuf) -> miette::Result<BTreeSet<String>> {
    let text: String = std::fs::read_to_string(path)
        .map_err(|e| miette::miette!("DR-FRISK-0063: cannot read baseline file: {e}"))?;
    let fingerprints: Vec<String> = serde_json::from_str(&text).map_err(|e| {
        miette::miette!("DR-FRISK-0064: baseline must be a JSON array of strings: {e}")
    })?;
    Ok(fingerprints.into_iter().collect())
}

fn render_text(report: &ReconReport) {
    if report.findings.is_empty() {
        println!("no findings");
    } else {
        for f in &report.findings {
            let loc: String = f.path.as_deref().map_or_else(
                || format!("@{}", f.offset),
                |p: &str| format!("{p}:{}:{}", f.line, f.column),
            );
            println!(
                "{loc}\t{}\t{}\t{}\t{}",
                f.severity,
                f.category.label(),
                f.rule_id,
                f.value
            );
        }
    }
    println!(
        "\n{} finding(s) across {} file(s), {} byte(s); {} non-utf8 file(s)",
        report.total, report.files_scanned, report.bytes_scanned, report.non_utf8_files
    );
}

fn render_git_text(report: &GitHistoryReport) {
    if report.findings.is_empty() {
        println!("no findings");
    } else {
        for gf in &report.findings {
            let short_sha: &str = gf.commit.get(..12).unwrap_or(gf.commit.as_str());
            println!(
                "{short_sha}\t{}\t{}\t{}\t{}\t{}",
                gf.author_email,
                gf.blob_path,
                gf.finding.severity,
                gf.finding.rule_id,
                gf.finding.value
            );
        }
    }
    println!(
        "\n{} finding(s) across {} commit(s), {} blob(s), {} byte(s)",
        report.total, report.commits_scanned, report.blobs_scanned, report.bytes_scanned
    );
}

fn git_to_sarif(report: &GitHistoryReport) -> SarifLog {
    let rule_set: BTreeSet<String> = report
        .findings
        .iter()
        .map(|gf: &GitFinding| gf.finding.rule_id.clone())
        .collect();
    let rules: Vec<ReportingDescriptor> = rule_set
        .into_iter()
        .map(|id: String| ReportingDescriptor {
            id,
            name: None,
            short_description: None,
        })
        .collect();
    let results: Vec<SarifResult> = report
        .findings
        .iter()
        .map(|gf: &GitFinding| {
            let short_sha: &str = gf.commit.get(..12).unwrap_or(gf.commit.as_str());
            SarifResult {
                rule_id: gf.finding.rule_id.clone(),
                level: sarif_level(&gf.finding.severity),
                message: Message {
                    text: format!(
                        "{} ({}) in commit {short_sha} by {}: {}",
                        gf.finding.category.label(),
                        gf.finding.rule_id,
                        gf.author_email,
                        gf.finding.value
                    ),
                },
                locations: vec![Location {
                    physical_location: PhysicalLocation {
                        artifact_location: ArtifactLocation {
                            uri: gf.blob_path.clone(),
                        },
                        region: Some(Region {
                            start_line: u32::try_from(gf.finding.line).unwrap_or(1),
                            start_column: Some(u32::try_from(gf.finding.column).unwrap_or(1)),
                            end_line: None,
                            end_column: None,
                        }),
                    },
                }],
            }
        })
        .collect();
    SarifLog::new(Driver::disrobe(rules), results)
}

fn run_git(
    path: PathBuf,
    format: FriskFormat,
    config: ReconConfig,
    fmt: OutputFormat,
    redactor: Option<Redactor>,
) -> miette::Result<()> {
    let opts: GitHistoryOptions = GitHistoryOptions {
        recon: config,
        ..GitHistoryOptions::default()
    };
    let label: String = path.display().to_string();
    let spinner: StageSpinner = StageSpinner::start(&label, "scanning git history for secrets");
    let mut report: GitHistoryReport =
        git_history::report_git(&path, &opts).map_err(|e| miette::miette!("DR-FRISK-0070: {e}"))?;
    spinner.finish(&format!(
        "{} finding(s), {} commit(s) scanned",
        report.total, report.commits_scanned
    ));

    if let Some(redactor) = &redactor {
        redactor.redact_git_report(&mut report);
    }

    let effective: FriskFormat = if fmt.is_machine() {
        if matches!(fmt, OutputFormat::Sarif) {
            FriskFormat::Sarif
        } else {
            FriskFormat::Json
        }
    } else {
        format
    };

    match effective {
        FriskFormat::Text => {
            render_git_text(&report);
            Ok(())
        }
        FriskFormat::Json => {
            let s: String = serde_json::to_string_pretty(&report)
                .map_err(|e| miette::miette!("DR-FRISK-0071: json serialize: {e}"))?;
            println!("{s}");
            Ok(())
        }
        FriskFormat::Sarif => {
            let log: SarifLog = git_to_sarif(&report);
            crate::cli::output::emit_sarif_log(&log)
        }
    }
}

fn sarif_level(severity: &str) -> SarifLevel {
    match severity {
        "error" => SarifLevel::Error,
        "warning" => SarifLevel::Warning,
        _ => SarifLevel::Note,
    }
}

fn to_sarif(report: &ReconReport) -> SarifLog {
    let rule_set: BTreeSet<String> = report
        .findings
        .iter()
        .map(|f: &ReconFinding| f.rule_id.clone())
        .collect();
    let rules: Vec<ReportingDescriptor> = rule_set
        .into_iter()
        .map(|id: String| ReportingDescriptor {
            id,
            name: None,
            short_description: None,
        })
        .collect();
    let results: Vec<SarifResult> = report
        .findings
        .iter()
        .map(|f: &ReconFinding| {
            let uri: String = f
                .path
                .clone()
                .or_else(|| report.root.clone())
                .unwrap_or_else(|| "input".to_owned());
            SarifResult {
                rule_id: f.rule_id.clone(),
                level: sarif_level(&f.severity),
                message: Message {
                    text: format!("{} ({}): {}", f.category.label(), f.rule_id, f.value),
                },
                locations: vec![Location {
                    physical_location: PhysicalLocation {
                        artifact_location: ArtifactLocation { uri },
                        region: Some(Region {
                            start_line: u32::try_from(f.line).unwrap_or(1),
                            start_column: Some(u32::try_from(f.column).unwrap_or(1)),
                            end_line: None,
                            end_column: None,
                        }),
                    },
                }],
            }
        })
        .collect();
    SarifLog::new(Driver::disrobe(rules), results)
}

#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
pub(crate) fn run(
    path: PathBuf,
    format: FriskFormat,
    pattern_file: Option<PathBuf>,
    suppress: Vec<String>,
    baseline: Option<PathBuf>,
    emit_baseline: bool,
    entropy: bool,
    git: bool,
    redact: bool,
    redact_key: Option<String>,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let redact: bool = redact || redact_key.is_some();
    if emit_baseline && redact {
        return Err(miette::miette!(
            "DR-FRISK-0080: --emit-baseline cannot be combined with --redact: a baseline must record raw values to match findings on a later scan"
        ));
    }
    let redactor: Option<Redactor> = redact.then(|| {
        redact_key
            .as_deref()
            .map_or_else(Redactor::with_random_key, Redactor::with_key)
    });

    let custom: Vec<CustomPattern> = match pattern_file {
        Some(p) => load_patterns(&p)?,
        None => Vec::new(),
    };
    let baseline_set: BTreeSet<String> = match baseline {
        Some(b) => load_baseline(&b)?,
        None => BTreeSet::new(),
    };
    let config: ReconConfig = ReconConfig {
        custom,
        suppress_substrings: suppress,
        include_high_entropy: entropy,
    };

    if git {
        return run_git(path, format, config, fmt, redactor);
    }

    let label: String = path.display().to_string();
    let spinner: StageSpinner = StageSpinner::start(&label, "scanning for secrets");
    let mut report: ReconReport =
        recon::report_tree(&path, &config).map_err(|e| miette::miette!("DR-FRISK-0050: {e}"))?;
    spinner.finish(&format!(
        "{} finding(s), {} file(s) scanned",
        report.total, report.files_scanned
    ));

    if !baseline_set.is_empty() {
        report
            .findings
            .retain(|f: &ReconFinding| !baseline_set.contains(&fingerprint(f)));
        report.total = report.findings.len();
    }

    if emit_baseline {
        let fingerprints: Vec<String> = report
            .findings
            .iter()
            .map(fingerprint)
            .collect::<Vec<String>>();
        let s: String = serde_json::to_string_pretty(&fingerprints)
            .map_err(|e| miette::miette!("DR-FRISK-0052: baseline serialize: {e}"))?;
        println!("{s}");
        return Ok(());
    }

    if let Some(redactor) = &redactor {
        redactor.redact_report(&mut report);
    }

    let effective: FriskFormat = if fmt.is_machine() {
        if matches!(fmt, OutputFormat::Sarif) {
            FriskFormat::Sarif
        } else {
            FriskFormat::Json
        }
    } else {
        format
    };

    match effective {
        FriskFormat::Text => {
            render_text(&report);
            Ok(())
        }
        FriskFormat::Json => {
            let s: String = serde_json::to_string_pretty(&report)
                .map_err(|e| miette::miette!("DR-FRISK-0051: json serialize: {e}"))?;
            println!("{s}");
            Ok(())
        }
        FriskFormat::Sarif => {
            let log: SarifLog = to_sarif(&report);
            crate::cli::output::emit_sarif_log(&log)
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn sarif_maps_findings_with_region() {
        let key: String = format!("{}{}", "AKIA", "3KFTG2KQ4WXYZ7AB");
        let input: String = format!("line\nkey {key} end");
        let report: ReconReport =
            recon::report_bytes(input.as_bytes(), Some("a.smali"), &ReconConfig::default());
        let log: SarifLog = to_sarif(&report);
        let v: serde_json::Value = serde_json::to_value(&log).expect("serialize");
        assert_eq!(v["version"], "2.1.0");
        let results: &Vec<serde_json::Value> = v["runs"][0]["results"].as_array().expect("results");
        assert!(
            results.iter().any(|r: &serde_json::Value| {
                r["ruleId"] == "DR-SEC-AWS-AKID"
                    && r["locations"][0]["physicalLocation"]["region"]["startLine"] == 2
            }),
            "aws finding must carry startLine 2: {results:?}"
        );
    }

    #[test]
    fn fingerprint_is_stable_for_baseline() {
        let key: String = format!("{}{}", "AKIA", "3KFTG2KQ4WXYZ7AB");
        let input: String = format!("key {key}");
        let report: ReconReport =
            recon::report_bytes(input.as_bytes(), Some("f.txt"), &ReconConfig::default());
        let aws: &ReconFinding = report
            .findings
            .iter()
            .find(|f: &&ReconFinding| f.rule_id == "DR-SEC-AWS-AKID")
            .expect("aws");
        assert_eq!(
            fingerprint(aws),
            "f.txt|secret|DR-SEC-AWS-AKID|AKIA\u{2026}20"
        );
    }
}
