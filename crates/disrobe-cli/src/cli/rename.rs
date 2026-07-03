#![allow(clippy::needless_pass_by_value)]
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::output::{OutputFormat, emit};
use crate::cli::llm::iso8601_now;

const RENAMES_SCHEMA: &str = "disrobe.renames/v1";

fn renames_schema() -> String {
    RENAMES_SCHEMA.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RenameRecord {
    old: String,
    new: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    recorded_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RenamesFile {
    #[serde(default = "renames_schema")]
    schema: String,
    records: Vec<RenameRecord>,
}

impl Default for RenamesFile {
    fn default() -> Self {
        Self {
            schema: RENAMES_SCHEMA.to_string(),
            records: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize)]
struct RenameReport {
    path: String,
    schema: String,
    old: String,
    new: String,
    record_count: usize,
}

fn load_or_default(path: &Path) -> miette::Result<RenamesFile> {
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(path) else {
        return Ok(RenamesFile::default());
    };
    serde_json::from_slice::<RenamesFile>(&bytes).map_err(|e: serde_json::Error| {
        miette::miette!(
            "DR-CLI-0330: {} is not a valid disrobe.renames/v1 file: {e}",
            path.display()
        )
    })
}

pub(crate) fn run(
    old: String,
    new: String,
    note: Option<String>,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let cwd: PathBuf = std::env::current_dir()
        .map_err(|e: std::io::Error| miette::miette!("DR-CLI-0331: cannot read cwd: {e}"))?;
    let disrobe: PathBuf = cwd.join(".disrobe");
    if !disrobe.is_dir() {
        return Err(miette::miette!(
            "DR-CLI-0332: no `.disrobe/` workspace in {} - run `disrobe init` first",
            cwd.display()
        ));
    }
    let notes_dir: PathBuf = disrobe.join("notes");
    std::fs::create_dir_all(&notes_dir).map_err(|e: std::io::Error| {
        miette::miette!("DR-CLI-0333: cannot create .disrobe/notes: {e}")
    })?;
    let path: PathBuf = notes_dir.join("renames.json");
    let mut file: RenamesFile = load_or_default(&path)?;
    file.records.push(RenameRecord {
        old: old.clone(),
        new: new.clone(),
        note,
        recorded_at: iso8601_now(),
    });
    let json: String = serde_json::to_string_pretty(&file)
        .map_err(|e: serde_json::Error| miette::miette!("DR-CLI-0334: renames serialize: {e}"))?;
    std::fs::write(&path, json.as_bytes()).map_err(|e: std::io::Error| {
        miette::miette!("DR-CLI-0335: cannot write {}: {e}", path.display())
    })?;
    let report: RenameReport = RenameReport {
        path: path.display().to_string(),
        schema: file.schema.clone(),
        old,
        new,
        record_count: file.records.len(),
    };
    emit(fmt, &report, || {
        println!("disrobe rename: recorded");
        println!("  {} -> {}", report.old, report.new);
        println!("  file:    {}", report.path);
        println!("  records: {}", report.record_count);
    })
}
