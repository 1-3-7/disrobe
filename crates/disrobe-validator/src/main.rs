#![deny(unreachable_pub)]
#![allow(clippy::print_stdout, clippy::print_stderr)]
use std::path::PathBuf;

use disrobe_validator::{build_report, run_sample, walk_corpus};

fn main() -> miette::Result<()> {
    tracing_subscriber::fmt::init();
    let root: PathBuf = std::env::args()
        .nth(1)
        .map_or_else(|| PathBuf::from("./corpus"), PathBuf::from);
    let out_path: PathBuf = std::env::args().nth(2).map_or_else(
        || PathBuf::from("./out/validation-report.json"),
        PathBuf::from,
    );

    let entries: Vec<disrobe_validator::CorpusEntry> = walk_corpus(&root);
    println!(
        "walking corpus {} -> {} entries",
        root.display(),
        entries.len()
    );

    let mut all_samples: Vec<disrobe_validator::SampleMetrics> = Vec::new();
    for entry in &entries {
        let samples: Vec<disrobe_validator::SampleMetrics> = run_sample(entry);
        all_samples.extend(samples);
    }

    let report: disrobe_validator::ValidationReport = build_report(all_samples);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("cannot create out dir: {e}"))?;
    }
    let report_bytes: Vec<u8> = serde_json::to_vec_pretty(&report)
        .map_err(|e: serde_json::Error| miette::miette!("cannot serialize report: {e}"))?;
    std::fs::write(&out_path, &report_bytes)
        .map_err(|e: std::io::Error| miette::miette!("cannot write report: {e}"))?;
    println!(
        "report: {} samples ({} ran-ok / {} recovered / {} failed) -> {}",
        report.total_samples,
        report.total_ok,
        report.total_recovered,
        report.total_failed,
        out_path.display()
    );
    for p in &report.per_pass {
        println!(
            "  {} : run={} ok={} recovered={} fail={} in={}B out={}B time={}us",
            p.pass_name,
            p.samples_run,
            p.samples_ok,
            p.samples_recovered,
            p.samples_failed,
            p.total_input_bytes,
            p.total_output_bytes,
            p.total_micros
        );
    }
    Ok(())
}
