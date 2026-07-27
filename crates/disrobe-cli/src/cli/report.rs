#![cfg(feature = "chain")]
#![allow(clippy::needless_pass_by_value)]
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use disrobe_core::chain::{ChainDocument, ChainRecoveryReport, NodeDoc};
use disrobe_core::recovery::ConfidenceTier;
use serde::Serialize;

use super::batch::{self, BatchManifest, BatchOptions};
use super::chain_v1::{self, ChainOutcome};
use super::output::OutputFormat;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ReportFormat {
    #[default]
    Text,
    Json,
    Markdown,
    Html,
}

#[derive(Debug, Serialize)]
pub(crate) struct StageView {
    pub(crate) index: usize,
    pub(crate) pass: String,
    pub(crate) verdict: String,
    pub(crate) confidence: &'static str,
    pub(crate) recovery_score: f64,
    pub(crate) duration_ms: Option<u128>,
    pub(crate) format_in: Option<String>,
    pub(crate) format_out: Option<String>,
    pub(crate) artifacts: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct InputIdentity {
    pub(crate) path: Option<String>,
    pub(crate) size: u64,
    pub(crate) blake3: String,
    pub(crate) detected: Vec<String>,
    pub(crate) final_format: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct TierTotals {
    pub(crate) exact: u32,
    pub(crate) semantic: u32,
    pub(crate) partial: u32,
    pub(crate) skeleton: u32,
    pub(crate) total: u32,
}

#[derive(Debug, Serialize)]
pub(crate) struct SingleReport {
    pub(crate) kind: &'static str,
    pub(crate) schema: String,
    pub(crate) tool_version: String,
    pub(crate) source_dir: Option<String>,
    pub(crate) input: InputIdentity,
    pub(crate) topology: String,
    pub(crate) verdict: String,
    pub(crate) total_ms: u128,
    pub(crate) recovery_score: f64,
    pub(crate) tiers: TierTotals,
    pub(crate) stages: Vec<StageView>,
    pub(crate) artifacts: Vec<String>,
    pub(crate) notes: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "report_kind", rename_all = "snake_case")]
enum ReportDocument {
    Single(Box<SingleReport>),
    Batch(Box<BatchReport>),
}

#[derive(Debug, Serialize)]
pub(crate) struct BatchFileView {
    pub(crate) relative: String,
    pub(crate) detected_format: Option<String>,
    pub(crate) chain: Vec<String>,
    pub(crate) verdict: Option<String>,
    pub(crate) recovery_score: Option<f64>,
    pub(crate) duration_ms: u128,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BatchReport {
    pub(crate) schema: String,
    pub(crate) tool_version: String,
    pub(crate) source_dir: String,
    pub(crate) root: String,
    pub(crate) chain: String,
    pub(crate) processed: usize,
    pub(crate) recovered: usize,
    pub(crate) detect_only: usize,
    pub(crate) errors: usize,
    pub(crate) mean_recovery_score: Option<f64>,
    pub(crate) files: Vec<BatchFileView>,
}

const RECOVERY_REPORT_SCHEMA: &str = "disrobe.report/v1";

pub(crate) fn tier_label(score: f64) -> &'static str {
    if score >= 0.99 {
        "exact"
    } else if score >= 0.66 {
        "semantic"
    } else if score >= 0.33 {
        "partial"
    } else {
        "skeleton"
    }
}

fn pass_score(pass: &disrobe_core::chain::ChainPassRecovery) -> f64 {
    f64::from(pass.confidence.rank()) / f64::from(ConfidenceTier::Exact.rank())
}

fn mean_score(report: &ChainRecoveryReport) -> f64 {
    if report.passes.is_empty() {
        return 0.0;
    }
    let sum: f64 = report.passes.iter().map(pass_score).sum();
    (sum / report.passes.len() as f64).clamp(0.0, 1.0)
}

fn node_for_pass<'a>(doc: &'a ChainDocument, pass_name: &str) -> Option<&'a NodeDoc> {
    doc.nodes
        .iter()
        .find(|n: &&NodeDoc| n.pass.as_deref() == Some(pass_name))
}

fn build_single(
    doc: &ChainDocument,
    recovery: &ChainRecoveryReport,
    source_dir: Option<&Path>,
) -> SingleReport {
    let mut all_artifacts: Vec<String> = Vec::new();
    let stages: Vec<StageView> = recovery
        .passes
        .iter()
        .enumerate()
        .map(
            |(idx, pass): (usize, &disrobe_core::chain::ChainPassRecovery)| {
                let node: Option<&NodeDoc> = node_for_pass(doc, &pass.name);
                let artifacts: Vec<String> = node
                    .map(|n: &NodeDoc| n.artifacts.clone())
                    .unwrap_or_default();
                for a in &artifacts {
                    if !all_artifacts.contains(a) {
                        all_artifacts.push(a.clone());
                    }
                }
                let score: f64 = pass_score(pass);
                StageView {
                    index: idx + 1,
                    pass: pass.name.clone(),
                    verdict: node.map_or_else(
                        || format!("{:?}", recovery.verdict),
                        |n: &NodeDoc| format!("{:?}", n.verdict),
                    ),
                    confidence: pass.confidence.as_str(),
                    recovery_score: score,
                    duration_ms: pass.duration_ms,
                    format_in: pass.format_in.clone(),
                    format_out: pass.format_out.clone(),
                    artifacts,
                }
            },
        )
        .collect();
    let mut notes: Vec<String> = Vec::new();
    if recovery.passes.is_empty() {
        notes.push(
            "detect-only: no pass executed (format recognized but not transformed)".to_string(),
        );
    }
    if recovery.histogram.skeleton > 0 {
        notes.push(format!(
            "{} skeleton-tier stage(s): structure recovered, bodies incomplete",
            recovery.histogram.skeleton
        ));
    }
    SingleReport {
        kind: "single",
        schema: RECOVERY_REPORT_SCHEMA.to_string(),
        tool_version: doc.tool_version.clone(),
        source_dir: source_dir.map(|p: &Path| p.display().to_string()),
        input: InputIdentity {
            path: doc.input.path.clone(),
            size: doc.input.size,
            blake3: doc.input.blake3.clone(),
            detected: doc.input.detected.clone(),
            final_format: doc.final_format.clone(),
        },
        topology: format!("{:?}", doc.topology),
        verdict: format!("{:?}", doc.verdict),
        total_ms: recovery.total_ms,
        recovery_score: mean_score(recovery),
        tiers: TierTotals {
            exact: recovery.histogram.exact,
            semantic: recovery.histogram.semantic,
            partial: recovery.histogram.partial,
            skeleton: recovery.histogram.skeleton,
            total: recovery.histogram.total(),
        },
        stages,
        artifacts: all_artifacts,
        notes,
    }
}

fn build_batch(manifest: &BatchManifest, source_dir: &Path) -> BatchReport {
    let files: Vec<BatchFileView> = manifest
        .entries
        .iter()
        .map(|e: &super::batch::ManifestEntry| BatchFileView {
            relative: e.relative.clone(),
            detected_format: e.detected_format.clone(),
            chain: e.chain.clone(),
            verdict: e.verdict.clone(),
            recovery_score: e.recovery_score,
            duration_ms: e.duration_ms,
            error: e.error.clone(),
        })
        .collect();
    let scored: Vec<f64> = manifest
        .entries
        .iter()
        .filter_map(|e: &super::batch::ManifestEntry| e.recovery_score)
        .collect();
    let mean_recovery_score: Option<f64> = if scored.is_empty() {
        None
    } else {
        Some(scored.iter().sum::<f64>() / scored.len() as f64)
    };
    BatchReport {
        schema: RECOVERY_REPORT_SCHEMA.to_string(),
        tool_version: manifest.tool_version.clone(),
        source_dir: source_dir.display().to_string(),
        root: manifest.root.clone(),
        chain: manifest.chain.clone(),
        processed: manifest.summary.processed,
        recovered: manifest.summary.recovered,
        detect_only: manifest.summary.detect_only,
        errors: manifest.summary.errors,
        mean_recovery_score,
        files,
    }
}

fn read_chain_doc(dir: &Path) -> miette::Result<ChainDocument> {
    let path: PathBuf = dir.join("chain.json");
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-CLI-0351: cannot read {}: {e}", path.display()))?;
    serde_json::from_slice::<ChainDocument>(&bytes).map_err(|e| {
        miette::miette!(
            "DR-CLI-0352: {} is not a valid chain.json: {e}",
            path.display()
        )
    })
}

fn read_recovery(dir: &Path) -> miette::Result<ChainRecoveryReport> {
    let path: PathBuf = dir.join("recovery.json");
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-CLI-0353: cannot read {}: {e}", path.display()))?;
    serde_json::from_slice::<ChainRecoveryReport>(&bytes).map_err(|e| {
        miette::miette!(
            "DR-CLI-0354: {} is not a valid recovery.json: {e}",
            path.display()
        )
    })
}

fn read_manifest(dir: &Path) -> miette::Result<BatchManifest> {
    let path: PathBuf = dir.join("manifest.json");
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-CLI-0355: cannot read {}: {e}", path.display()))?;
    serde_json::from_slice::<BatchManifest>(&bytes).map_err(|e| {
        miette::miette!(
            "DR-CLI-0356: {} is not a valid manifest.json: {e}",
            path.display()
        )
    })
}

fn derived_out_dir(input: &Path, base: Option<&Path>) -> PathBuf {
    let stem: &str = input
        .file_stem()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .filter(|s: &&str| !s.is_empty())
        .unwrap_or("report");
    base.map_or_else(
        || PathBuf::from(format!("./out/{stem}-auto")),
        |root: &Path| root.join(format!("{stem}-auto")),
    )
}

fn derived_batch_dir(input: &Path, base: Option<&Path>) -> PathBuf {
    let stem: &str = input
        .file_name()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .filter(|s: &&str| !s.is_empty())
        .unwrap_or("batch");
    base.map_or_else(
        || PathBuf::from(format!("./out/{stem}-batch")),
        |root: &Path| root.join(format!("{stem}-batch")),
    )
}

fn resolve_document(target: &Path, base: Option<&Path>) -> miette::Result<ReportDocument> {
    if target.is_dir() {
        if target.join("manifest.json").is_file() {
            let manifest: BatchManifest = read_manifest(target)?;
            return Ok(ReportDocument::Batch(Box::new(build_batch(
                &manifest, target,
            ))));
        }
        if target.join("chain.json").is_file() {
            let doc: ChainDocument = read_chain_doc(target)?;
            let recovery: ChainRecoveryReport = read_recovery(target)?;
            return Ok(ReportDocument::Single(Box::new(build_single(
                &doc,
                &recovery,
                Some(target),
            ))));
        }
        let out_dir: PathBuf = derived_batch_dir(target, base);
        let opts: BatchOptions = BatchOptions {
            out_root: out_dir.clone(),
            chain_arg: "auto:8".to_string(),
            max_depth: None,
            include: Vec::new(),
            exclude: Vec::new(),
            jobs: 1,
            capture_stages: false,
            i_have_authorization: false,
        };
        let manifest: BatchManifest = batch::compute_manifest(target, &opts)?;
        return Ok(ReportDocument::Batch(Box::new(build_batch(
            &manifest, &out_dir,
        ))));
    }
    if target.is_file() {
        let out_dir: PathBuf = derived_out_dir(target, base);
        let bytes: Vec<u8> = std::fs::read(target).map_err(|e| {
            miette::miette!(
                "DR-CLI-0358: cannot read report input {}: {e}",
                target.display()
            )
        })?;
        let outcome: ChainOutcome = chain_v1::run_chain_to_dir(
            &target.display().to_string(),
            bytes,
            &out_dir,
            "auto:8",
            false,
            false,
        )?;
        return Ok(ReportDocument::Single(Box::new(build_single(
            &outcome.doc,
            &outcome.report,
            Some(&out_dir),
        ))));
    }
    Err(miette::miette!(
        "DR-CLI-0350: report target does not exist: {}",
        target.display()
    ))
}

fn render_text_single(r: &SingleReport, out: &mut String) {
    let _ = writeln!(out, "disrobe report  ({})", r.kind);
    let _ = writeln!(out, "  tool:        {}", r.tool_version);
    if let Some(src) = r.source_dir.as_deref() {
        let _ = writeln!(out, "  source:      {src}");
    }
    let _ = writeln!(
        out,
        "  input:       {} ({} bytes)",
        r.input.path.as_deref().unwrap_or("(unknown)"),
        r.input.size
    );
    let _ = writeln!(out, "  blake3:      {}", r.input.blake3);
    if !r.input.detected.is_empty() {
        let _ = writeln!(out, "  detected:    {}", r.input.detected.join(" -> "));
    }
    if let Some(ff) = r.input.final_format.as_deref() {
        let _ = writeln!(out, "  final:       {ff}");
    }
    let _ = writeln!(out, "  topology:    {}", r.topology);
    let _ = writeln!(out, "  verdict:     {}", r.verdict);
    let _ = writeln!(
        out,
        "  recovery:    {:.0}% ({})",
        r.recovery_score * 100.0,
        tier_label(r.recovery_score)
    );
    let _ = writeln!(
        out,
        "  tiers:       exact={} semantic={} partial={} skeleton={} (total {})",
        r.tiers.exact, r.tiers.semantic, r.tiers.partial, r.tiers.skeleton, r.tiers.total
    );
    let _ = writeln!(out, "  total_ms:    {}", r.total_ms);
    let _ = writeln!(out, "  stages:");
    for s in &r.stages {
        let _ = writeln!(
            out,
            "    {:>2}. {:<26} {:<10} {:>3.0}%  {}",
            s.index,
            s.pass,
            s.confidence,
            s.recovery_score * 100.0,
            s.duration_ms
                .map_or_else(|| "-".to_string(), |d: u128| format!("{d}ms"))
        );
    }
    if !r.artifacts.is_empty() {
        let _ = writeln!(out, "  artifacts:");
        for a in &r.artifacts {
            let _ = writeln!(out, "    - {a}");
        }
    }
    for note in &r.notes {
        let _ = writeln!(out, "  note:        {note}");
    }
}

fn render_text_batch(r: &BatchReport, out: &mut String) {
    let _ = writeln!(out, "disrobe report  (batch)");
    let _ = writeln!(out, "  tool:        {}", r.tool_version);
    let _ = writeln!(out, "  source:      {}", r.source_dir);
    let _ = writeln!(out, "  root:        {}", r.root);
    let _ = writeln!(out, "  chain:       {}", r.chain);
    let _ = writeln!(
        out,
        "  files:       {} processed, {} recovered, {} detect-only, {} errors",
        r.processed, r.recovered, r.detect_only, r.errors
    );
    if let Some(mean) = r.mean_recovery_score {
        let _ = writeln!(out, "  mean score:  {:.0}%", mean * 100.0);
    }
    let _ = writeln!(out, "  per-file:");
    for f in &r.files {
        let status: &str = if f.error.is_some() {
            "ERR "
        } else if f.chain.is_empty() {
            "scan"
        } else {
            "ok  "
        };
        let score: String = f
            .recovery_score
            .map_or_else(|| "-".to_string(), |s: f64| format!("{:.0}%", s * 100.0));
        let _ = writeln!(
            out,
            "    [{status}] {:<44} {:<5} {}",
            f.relative,
            score,
            f.error.as_deref().unwrap_or("")
        );
    }
}

fn render_markdown_single(r: &SingleReport, out: &mut String) {
    let _ = writeln!(out, "# disrobe report");
    let _ = writeln!(out);
    let _ = writeln!(out, "| field | value |");
    let _ = writeln!(out, "|---|---|");
    let _ = writeln!(
        out,
        "| input | `{}` |",
        r.input.path.as_deref().unwrap_or("(unknown)")
    );
    let _ = writeln!(out, "| size | {} bytes |", r.input.size);
    let _ = writeln!(out, "| blake3 | `{}` |", r.input.blake3);
    if let Some(ff) = r.input.final_format.as_deref() {
        let _ = writeln!(out, "| final format | {ff} |");
    }
    let _ = writeln!(out, "| topology | {} |", r.topology);
    let _ = writeln!(out, "| verdict | {} |", r.verdict);
    let _ = writeln!(
        out,
        "| recovery | {:.0}% ({}) |",
        r.recovery_score * 100.0,
        tier_label(r.recovery_score)
    );
    let _ = writeln!(out, "| total | {} ms |", r.total_ms);
    let _ = writeln!(out);
    let _ = writeln!(out, "## Stages");
    let _ = writeln!(out);
    let _ = writeln!(out, "| # | pass | confidence | score | duration |");
    let _ = writeln!(out, "|---:|---|---|---:|---:|");
    for s in &r.stages {
        let _ = writeln!(
            out,
            "| {} | `{}` | {} | {:.0}% | {} |",
            s.index,
            s.pass,
            s.confidence,
            s.recovery_score * 100.0,
            s.duration_ms
                .map_or_else(|| "-".to_string(), |d: u128| format!("{d} ms"))
        );
    }
    if !r.artifacts.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "## Recovered artifacts");
        let _ = writeln!(out);
        for a in &r.artifacts {
            let _ = writeln!(out, "- `{a}`");
        }
    }
    if !r.notes.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "## Notes");
        let _ = writeln!(out);
        for note in &r.notes {
            let _ = writeln!(out, "- {note}");
        }
    }
}

fn render_markdown_batch(r: &BatchReport, out: &mut String) {
    let _ = writeln!(out, "# disrobe report (batch)");
    let _ = writeln!(out);
    let _ = writeln!(out, "- root: `{}`", r.root);
    let _ = writeln!(out, "- chain: `{}`", r.chain);
    let _ = writeln!(
        out,
        "- {} processed, {} recovered, {} detect-only, {} errors",
        r.processed, r.recovered, r.detect_only, r.errors
    );
    if let Some(mean) = r.mean_recovery_score {
        let _ = writeln!(out, "- mean recovery score: {:.0}%", mean * 100.0);
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "| file | format | score | status |");
    let _ = writeln!(out, "|---|---|---:|---|");
    for f in &r.files {
        let status: &str = if f.error.is_some() {
            "error"
        } else if f.chain.is_empty() {
            "detect-only"
        } else {
            "recovered"
        };
        let score: String = f
            .recovery_score
            .map_or_else(|| "-".to_string(), |s: f64| format!("{:.0}%", s * 100.0));
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} |",
            f.relative,
            f.detected_format.as_deref().unwrap_or("-"),
            score,
            status
        );
    }
}

pub(crate) fn run(
    target: PathBuf,
    format: ReportFormat,
    fmt: OutputFormat,
    out: Option<PathBuf>,
) -> miette::Result<()> {
    let document: ReportDocument = resolve_document(&target, out.as_deref())?;
    let effective: ReportFormat = if fmt.is_machine() {
        ReportFormat::Json
    } else {
        format
    };
    match effective {
        ReportFormat::Json => {
            let s: String = serde_json::to_string_pretty(&document)
                .map_err(|e| miette::miette!("DR-CLI-0357: report serialize: {e}"))?;
            println!("{s}");
            Ok(())
        }
        ReportFormat::Text => {
            let mut buf: String = String::new();
            match &document {
                ReportDocument::Single(s) => render_text_single(s, &mut buf),
                ReportDocument::Batch(b) => render_text_batch(b, &mut buf),
            }
            print!("{buf}");
            Ok(())
        }
        ReportFormat::Markdown => {
            let mut buf: String = String::new();
            match &document {
                ReportDocument::Single(s) => render_markdown_single(s, &mut buf),
                ReportDocument::Batch(b) => render_markdown_batch(b, &mut buf),
            }
            print!("{buf}");
            Ok(())
        }
        ReportFormat::Html => {
            let html: String = match &document {
                ReportDocument::Single(s) => {
                    let enrichment: super::report_html::Enrichment =
                        super::report_html::enrich_single(s);
                    super::report_html::render_single_html(s, &enrichment)
                }
                ReportDocument::Batch(b) => super::report_html::render_batch_html(b),
            };
            print!("{html}");
            Ok(())
        }
    }
}

#[cfg(test)]
pub(crate) const fn tier_totals_for_test(
    exact: u32,
    semantic: u32,
    partial: u32,
    skeleton: u32,
) -> TierTotals {
    TierTotals {
        exact,
        semantic,
        partial,
        skeleton,
        total: exact + semantic + partial + skeleton,
    }
}

#[cfg(test)]
pub(crate) fn batch_report_for_test() -> BatchReport {
    BatchReport {
        schema: RECOVERY_REPORT_SCHEMA.to_string(),
        tool_version: "0.9.0".to_string(),
        source_dir: "out/samples-batch".to_string(),
        root: "samples".to_string(),
        chain: "auto:8".to_string(),
        processed: 2,
        recovered: 1,
        detect_only: 0,
        errors: 1,
        mean_recovery_score: Some(0.67),
        files: vec![
            BatchFileView {
                relative: "a.pyc".to_string(),
                detected_format: Some("Python".to_string()),
                chain: vec!["py.decompile".to_string()],
                verdict: Some("Complete".to_string()),
                recovery_score: Some(0.67),
                duration_ms: 5,
                error: None,
            },
            BatchFileView {
                relative: "bad".to_string(),
                detected_format: None,
                chain: Vec::new(),
                verdict: None,
                recovery_score: None,
                duration_ms: 1,
                error: Some("read failed".to_string()),
            },
        ],
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::float_cmp,
    clippy::panic
)]
mod tests {
    use super::*;
    use disrobe_core::scratch::ScratchDir;

    fn tmp_dir(stem: &str) -> ScratchDir {
        let purpose: String = format!("disrobe-report-{stem}");
        ScratchDir::create(&purpose).expect("create scratch directory")
    }

    const CHAIN_JSON: &str = r#"{
      "schema": "disrobe.chain/v1",
      "tool_version": "0.9.0",
      "input": { "path": "app.pyc", "blake3": "abcd", "size": 128, "detected": ["pyc-3.11"] },
      "spec": { "raw": "auto:8", "kind": "auto", "cap": 8 },
      "topology": "linear",
      "root_node_id": 0,
      "nodes": [
        { "id": 0, "parent_id": null, "depth": 0, "branch_id": "root",
          "pass": null, "format_tag_in": null, "input_blake3": "abcd", "input_size": 128,
          "output_kind": null, "output_blake3": null, "output_size": null,
          "duration_ms": null, "detector_picks": [], "artifacts": [], "metadata": {},
          "verdict": "ok", "error": null },
        { "id": 1, "parent_id": 0, "depth": 1, "branch_id": "root",
          "pass": "py.decompile", "format_tag_in": "pyc-3.11", "input_blake3": "abcd", "input_size": 128,
          "output_kind": { "kind": "source", "language": "Python", "formatted": true },
          "output_blake3": "ef01", "output_size": 64,
          "duration_ms": 7, "detector_picks": [], "artifacts": ["app.py"], "metadata": {},
          "verdict": "complete", "error": null }
      ],
      "verdict": "complete",
      "final_format": "Python",
      "stats": { "layers": 1, "branches": 1, "total_ms": 7,
        "max_branch_depth": 1, "detector_calls": 1, "rejected_passes": 0 }
    }"#;

    const RECOVERY_JSON: &str = r#"{
      "schema": "disrobe.recovery/v1",
      "tool_version": "0.9.0",
      "input": { "path": "app.pyc", "blake3": "abcd", "size": 128 },
      "passes": [
        { "name": "py.decompile", "status": "recovered", "confidence": "semantic",
          "duration_ms": 7, "format_in": "pyc-3.11", "format_out": "Python" }
      ],
      "histogram": { "exact": 0, "semantic": 1, "partial": 0, "skeleton": 0 },
      "total_ms": 7,
      "verdict": "complete"
    }"#;

    fn seed_single_dir(stem: &str) -> (ScratchDir, PathBuf) {
        let scratch: ScratchDir = tmp_dir(stem);
        let dir: PathBuf = scratch.path().to_path_buf();
        std::fs::write(dir.join("chain.json"), CHAIN_JSON).expect("w chain");
        std::fs::write(dir.join("recovery.json"), RECOVERY_JSON).expect("w recovery");
        (scratch, dir)
    }

    #[test]
    fn tier_label_thresholds() {
        assert_eq!(tier_label(1.0), "exact");
        assert_eq!(tier_label(0.67), "semantic");
        assert_eq!(tier_label(0.5), "partial");
        assert_eq!(tier_label(0.1), "skeleton");
    }

    #[test]
    fn resolves_single_out_dir() {
        let (_scratch, dir): (ScratchDir, PathBuf) = seed_single_dir("single");
        let doc: ReportDocument = resolve_document(&dir, None).expect("resolve single");
        match doc {
            ReportDocument::Single(s) => {
                assert_eq!(s.input.path.as_deref(), Some("app.pyc"));
                assert_eq!(s.input.size, 128);
                assert_eq!(s.stages.len(), 1);
                assert_eq!(s.stages[0].pass, "py.decompile");
                assert_eq!(s.stages[0].confidence, "semantic");
                assert!((s.recovery_score - 0.6666).abs() < 0.01);
                assert!(s.artifacts.contains(&"app.py".to_string()));
            }
            ReportDocument::Batch(_) => panic!("expected single report"),
        }
    }

    #[test]
    fn text_render_contains_key_fields() {
        let (_scratch, dir): (ScratchDir, PathBuf) = seed_single_dir("text");
        let doc: ReportDocument = resolve_document(&dir, None).expect("resolve");
        let ReportDocument::Single(s) = doc else {
            panic!("single");
        };
        let mut buf: String = String::new();
        render_text_single(&s, &mut buf);
        assert!(buf.contains("py.decompile"), "got: {buf}");
        assert!(buf.contains("blake3:"), "got: {buf}");
        assert!(buf.contains("app.py"), "artifact inventory missing: {buf}");
    }

    #[test]
    fn markdown_render_is_tabular() {
        let (_scratch, dir): (ScratchDir, PathBuf) = seed_single_dir("md");
        let doc: ReportDocument = resolve_document(&dir, None).expect("resolve");
        let ReportDocument::Single(s) = doc else {
            panic!("single");
        };
        let mut buf: String = String::new();
        render_markdown_single(&s, &mut buf);
        assert!(buf.starts_with("# disrobe report"), "got: {buf}");
        assert!(buf.contains("## Stages"), "got: {buf}");
        assert!(buf.contains("| `py.decompile` |"), "got: {buf}");
    }

    #[test]
    fn json_document_round_trips_as_value() {
        let (_scratch, dir): (ScratchDir, PathBuf) = seed_single_dir("json");
        let doc: ReportDocument = resolve_document(&dir, None).expect("resolve");
        let value: serde_json::Value = serde_json::to_value(&doc).expect("to value");
        assert_eq!(value["report_kind"], serde_json::json!("single"));
        assert_eq!(value["input"]["size"], serde_json::json!(128));
        assert_eq!(
            value["stages"][0]["pass"],
            serde_json::json!("py.decompile")
        );
    }

    #[test]
    fn resolves_batch_out_dir() {
        let scratch: ScratchDir = tmp_dir("batch");
        let dir: PathBuf = scratch.path().to_path_buf();
        let manifest: &str = r#"{
          "schema": "disrobe.batch.manifest/v1",
          "tool_version": "0.9.0",
          "root": "samples",
          "out_root": "out/samples-batch",
          "chain": "auto:8",
          "jobs": 1,
          "summary": { "processed": 2, "recovered": 1, "detect_only": 0, "errors": 1 },
          "entries": [
            { "input": "samples/a.pyc", "relative": "a.pyc", "size": 64,
              "detected_format": "Python", "chain": ["py.decompile"], "verdict": "Complete",
              "recovery_score": 0.67, "output_dir": "out/samples-batch/a.pyc",
              "duration_ms": 5, "error": null },
            { "input": "samples/bad", "relative": "bad", "size": 0,
              "detected_format": null, "chain": [], "verdict": null,
              "recovery_score": null, "output_dir": null, "duration_ms": 1,
              "error": "read failed" }
          ]
        }"#;
        std::fs::write(dir.join("manifest.json"), manifest).expect("w manifest");
        let doc: ReportDocument = resolve_document(&dir, None).expect("resolve batch");
        let ReportDocument::Batch(b) = doc else {
            panic!("expected batch report");
        };
        assert_eq!(b.processed, 2);
        assert_eq!(b.errors, 1);
        assert_eq!(b.files.len(), 2);
        assert_eq!(b.mean_recovery_score, Some(0.67));
        let mut buf: String = String::new();
        render_markdown_batch(&b, &mut buf);
        assert!(buf.contains("# disrobe report (batch)"), "got: {buf}");
        assert!(buf.contains("error"), "errored file must show; got: {buf}");
    }

    #[test]
    fn missing_target_is_error() {
        let scratch: ScratchDir = tmp_dir("missing");
        let missing: PathBuf = scratch.path().join("nope");
        let err: miette::Report = resolve_document(&missing, None).expect_err("must error");
        assert!(format!("{err}").contains("DR-CLI-0350"));
    }

    #[test]
    fn without_a_chosen_root_the_derived_run_lands_under_the_working_directory() {
        let single: PathBuf = derived_out_dir(Path::new("sample.bin"), None);
        assert_eq!(single, PathBuf::from("./out/sample-auto"));
        let batch: PathBuf = derived_batch_dir(Path::new("corpus"), None);
        assert_eq!(batch, PathBuf::from("./out/corpus-batch"));
    }

    #[test]
    fn a_chosen_root_takes_the_derived_run_out_of_the_working_directory() {
        let scratch: ScratchDir = tmp_dir("chosen-root");
        let root: PathBuf = scratch.path().to_path_buf();
        let single: PathBuf = derived_out_dir(Path::new("sample.bin"), Some(&root));
        assert_eq!(single, root.join("sample-auto"));
        assert!(
            !single.starts_with("./out"),
            "a chosen root must not still write beside the working directory: {}",
            single.display()
        );
        let batch: PathBuf = derived_batch_dir(Path::new("corpus"), Some(&root));
        assert_eq!(batch, root.join("corpus-batch"));
    }
}
