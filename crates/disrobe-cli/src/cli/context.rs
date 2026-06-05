#![allow(clippy::needless_pass_by_value)]

use std::path::{Path, PathBuf};

use disrobe_core::chain::{ChainPassRecovery, ChainRecoveryReport, VerdictDoc};
use disrobe_core::recovery::{ConfidenceTier, TierHistogram};
use serde::Serialize;

use super::output::{OutputFormat, emit};

#[derive(Debug, Serialize)]
struct PassRow {
    name: String,
    status: &'static str,
    confidence: &'static str,
    duration_ms: Option<u128>,
    format_in: Option<String>,
    format_out: Option<String>,
}

#[derive(Debug, Serialize)]
struct HistogramView {
    exact: u32,
    semantic: u32,
    partial: u32,
    skeleton: u32,
    total: u32,
}

#[derive(Debug, Serialize)]
struct InputView {
    path: Option<String>,
    blake3: String,
    size: u64,
}

#[derive(Debug, Serialize)]
struct ContextReport {
    out_dir: String,
    schema: String,
    tool_version: String,
    input: InputView,
    verdict: VerdictDoc,
    terminal_reason: Option<String>,
    total_ms: u128,
    histogram: HistogramView,
    passes: Vec<PassRow>,
}

fn load_recovery(path: &Path) -> miette::Result<ChainRecoveryReport> {
    let bytes: Vec<u8> = std::fs::read(path).map_err(|_e: std::io::Error| {
        miette::miette!(
            "DR-CLI-0320: no recovery.json at {} - run `disrobe chain <input>` or `disrobe auto <input>` first, then pass --out <its out dir>",
            path.display()
        )
    })?;
    serde_json::from_slice::<ChainRecoveryReport>(&bytes).map_err(|e: serde_json::Error| {
        miette::miette!(
            "DR-CLI-0321: {} is not a valid disrobe.recovery/v1 report: {e}",
            path.display()
        )
    })
}

fn read_terminal_reason(out_dir: &Path) -> Option<String> {
    let chain_json: PathBuf = out_dir.join("chain.json");
    let text: String = std::fs::read_to_string(&chain_json).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    value
        .get("terminal_reason")
        .and_then(|v: &serde_json::Value| v.as_str())
        .map(str::to_owned)
}

pub(crate) fn run(out: Option<PathBuf>, fmt: OutputFormat) -> miette::Result<()> {
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from("./out"));
    let recovery_path: PathBuf = out_dir.join("recovery.json");
    let report: ChainRecoveryReport = load_recovery(&recovery_path)?;
    let histogram: TierHistogram = report.histogram;
    let passes: Vec<PassRow> = report
        .passes
        .iter()
        .map(|p: &ChainPassRecovery| PassRow {
            name: p.name.clone(),
            status: p.status.as_str(),
            confidence: p.confidence.as_str(),
            duration_ms: p.duration_ms,
            format_in: p.format_in.clone(),
            format_out: p.format_out.clone(),
        })
        .collect();
    let context_report: ContextReport = ContextReport {
        out_dir: out_dir.display().to_string(),
        schema: report.schema.clone(),
        tool_version: report.tool_version.clone(),
        input: InputView {
            path: report.input.path.clone(),
            blake3: report.input.blake3.clone(),
            size: report.input.size,
        },
        verdict: report.verdict.clone(),
        terminal_reason: read_terminal_reason(&out_dir),
        total_ms: report.total_ms,
        histogram: HistogramView {
            exact: histogram.get(ConfidenceTier::Exact),
            semantic: histogram.get(ConfidenceTier::Semantic),
            partial: histogram.get(ConfidenceTier::Partial),
            skeleton: histogram.get(ConfidenceTier::Skeleton),
            total: histogram.total(),
        },
        passes,
    };
    emit(fmt, &context_report, || {
        println!("disrobe context  ({})", context_report.out_dir);
        println!("  schema:    {}", context_report.schema);
        println!("  tool:      {}", context_report.tool_version);
        println!(
            "  input:     {} ({} bytes, blake3 {})",
            context_report.input.path.as_deref().unwrap_or("(stdin)"),
            context_report.input.size,
            context_report.input.blake3
        );
        println!("  verdict:   {:?}", context_report.verdict);
        if let Some(ref reason) = context_report.terminal_reason {
            println!("  terminal:  {reason}");
        }
        println!("  total_ms:  {}", context_report.total_ms);
        println!(
            "  tiers:     exact={} semantic={} partial={} skeleton={} (total {})",
            context_report.histogram.exact,
            context_report.histogram.semantic,
            context_report.histogram.partial,
            context_report.histogram.skeleton,
            context_report.histogram.total
        );
        println!("  passes:");
        for row in &context_report.passes {
            println!(
                "    {:<28} {:<10} {:<9} {}",
                row.name,
                row.status,
                row.confidence,
                row.duration_ms
                    .map_or_else(|| "-".to_string(), |d: u128| format!("{d}ms"))
            );
        }
    })
}
