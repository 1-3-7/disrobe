#![forbid(unsafe_code)]
#![cfg(feature = "chain")]

pub mod circular;
pub mod manifest;
pub mod oracle;
pub mod report;
pub mod runner;

pub use circular::{CircularityFinding, CircularityKind, CircularityReport, scan_circularity};
pub use manifest::{ManifestIndex, OracleFixture};
pub use oracle::{OracleKind, OracleVerdict};
pub use report::{OracleKindRow, PlaygroundReport, render_json, render_tsv};
pub use runner::{Runner, RunnerConfig};

use std::path::{Path, PathBuf};

#[must_use]
pub fn workspace_root_from(manifest_dir: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p
}

#[must_use]
pub fn corpus_root(workspace_root: &Path) -> PathBuf {
    workspace_root.join("corpus")
}
