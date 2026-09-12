#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![cfg(feature = "chain")]
pub mod circular;
pub mod manifest;
pub mod native_match;
pub mod oracle;
pub mod report;
pub mod runner;
pub mod wasm;

pub use circular::{CircularityFinding, CircularityKind, CircularityReport, scan_circularity};
pub use manifest::{ManifestIndex, OracleFixture};
pub use native_match::{NativeMatchRequest, NativeMatchUploadError, match_native_uploads};
pub use oracle::{OracleKind, OracleVerdict};
pub use report::{OracleKindRow, PlaygroundReport, render_json, render_tsv};
pub use runner::{Runner, RunnerConfig};
pub use wasm::{
    WasmSourceCoverage, WasmSourceLift, WasmSourceLiftError, WasmSourceTarget, lift_wasm_source,
};

use std::fs;
use std::io::Read as _;
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

fn read_text_bounded(path: &Path, max_bytes: u64) -> Option<String> {
    let metadata: fs::Metadata = fs::metadata(path).ok()?;
    if metadata.len() > max_bytes {
        return None;
    }
    let reserve: usize =
        usize::try_from(metadata.len().min(max_bytes)).map_or(0, |value: usize| value);
    let file: fs::File = fs::File::open(path).ok()?;
    let mut reader: std::io::Take<fs::File> = file.take(max_bytes.saturating_add(1));
    let mut bytes: Vec<u8> = Vec::with_capacity(reserve);
    reader.read_to_end(&mut bytes).ok()?;
    let len: u64 = u64::try_from(bytes.len()).map_or(u64::MAX, |value: u64| value);
    if len > max_bytes {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod fileio_tests {
    use super::*;

    #[test]
    fn text_reader_rejects_oversized_input() -> core::result::Result<(), String> {
        let dir: tempfile::TempDir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let path: PathBuf = dir.path().join("oversized.txt");
        fs::write(&path, "abcdef").map_err(|e| e.to_string())?;
        assert!(read_text_bounded(&path, 5).is_none());
        Ok(())
    }
}
