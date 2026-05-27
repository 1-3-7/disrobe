#![allow(clippy::needless_pass_by_value)]

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;

use super::output::{OutputFormat, emit};

#[derive(Debug, Serialize)]
pub(crate) struct StatusReport {
    pub cwd: String,
    pub out_dir_present: bool,
    pub stages: Vec<StageSummary>,
    pub total_artifacts: u64,
    pub total_bytes: u64,
    pub chain_terminal_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct StageSummary {
    pub dir: String,
    pub artifacts: u64,
    pub bytes: u64,
    pub last_modified_secs_since_epoch: Option<u64>,
    pub has_manifest: bool,
}

pub(crate) fn run(fmt: OutputFormat) -> miette::Result<()> {
    let cwd: PathBuf = std::env::current_dir()
        .map_err(|e| miette::miette!("DR-CLI-0150: cannot read cwd: {e}"))?;
    let out_dir: PathBuf = cwd.join("out");
    if !out_dir.is_dir() {
        let report: StatusReport = StatusReport {
            cwd: cwd.display().to_string(),
            out_dir_present: false,
            stages: Vec::new(),
            total_artifacts: 0,
            total_bytes: 0,
            chain_terminal_reason: None,
        };
        return emit(fmt, &report, || {
            println!("disrobe status");
            println!("  cwd: {}", report.cwd);
            println!("  no `./out/` directory detected — no disrobe run to summarize");
        });
    }

    let mut stages: Vec<StageSummary> = Vec::new();
    let mut total_artifacts: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut chain_terminal_reason: Option<String> = None;

    let chain_json_path: PathBuf = out_dir.join("chain.json");
    if chain_json_path.is_file()
        && let Ok(text) = std::fs::read_to_string(&chain_json_path)
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(reason) = value.get("terminal_reason").and_then(|v| v.as_str())
    {
        chain_terminal_reason = Some(reason.to_owned());
    }

    let entries: Vec<PathBuf> = match std::fs::read_dir(&out_dir) {
        Ok(rd) => rd.filter_map(|e| e.ok().map(|d| d.path())).collect(),
        Err(e) => return Err(miette::miette!("DR-CLI-0150: cannot read out/: {e}")),
    };
    let mut sorted: Vec<PathBuf> = entries.into_iter().filter(|p| p.is_dir()).collect();
    sorted.sort();

    for dir in &sorted {
        let mut artifacts: u64 = 0;
        let mut bytes: u64 = 0;
        let mut has_manifest: bool = false;
        let mut latest: Option<u64> = None;
        walk(dir, &mut |path, meta| {
            artifacts += 1;
            bytes += meta.len();
            if path.file_name().is_some_and(|n| n == "manifest.json") {
                has_manifest = true;
            }
            if let Ok(mtime) = meta.modified()
                && let Ok(d) = mtime.duration_since(SystemTime::UNIX_EPOCH)
            {
                let secs: u64 = d.as_secs();
                latest = Some(latest.map_or(secs, |x| x.max(secs)));
            }
        });
        total_artifacts += artifacts;
        total_bytes += bytes;
        stages.push(StageSummary {
            dir: dir.display().to_string(),
            artifacts,
            bytes,
            last_modified_secs_since_epoch: latest,
            has_manifest,
        });
    }

    let report: StatusReport = StatusReport {
        cwd: cwd.display().to_string(),
        out_dir_present: true,
        stages,
        total_artifacts,
        total_bytes,
        chain_terminal_reason,
    };

    emit(fmt, &report, || {
        println!("disrobe status");
        println!("  cwd:               {}", report.cwd);
        println!("  out/ present:      {}", report.out_dir_present);
        println!("  stages:            {}", report.stages.len());
        println!("  total artifacts:   {}", report.total_artifacts);
        println!("  total bytes:       {}", report.total_bytes);
        if let Some(ref r) = report.chain_terminal_reason {
            println!("  chain terminal:    {r}");
        }
        for s in &report.stages {
            println!(
                "    {:<70} artifacts={:<4} bytes={:<10} manifest={}",
                s.dir, s.artifacts, s.bytes, s.has_manifest
            );
        }
    })
}

fn walk(dir: &Path, on_file: &mut dyn FnMut(&Path, &std::fs::Metadata)) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            walk(&path, on_file);
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            on_file(&path, &meta);
        }
    }
}
