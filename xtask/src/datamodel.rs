use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr};
use serde::Deserialize;

use crate::fileio::read_text_bounded;

const MAX_DATA_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub(crate) struct VerificationDoc {
    pub(crate) rows: Vec<VerificationRow>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VerificationRow {
    pub(crate) ecosystem: String,
    #[serde(default)]
    pub(crate) result: String,
}

pub(crate) fn verification_path(root: &Path) -> PathBuf {
    root.join("xtask").join("data").join("verification.json")
}

pub(crate) fn load_verification(root: &Path) -> Result<VerificationDoc> {
    let path: PathBuf = verification_path(root);
    let text: String = read_text_bounded(&path, MAX_DATA_BYTES)
        .wrap_err_with(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).wrap_err_with(|| format!("parsing {}", path.display()))
}
