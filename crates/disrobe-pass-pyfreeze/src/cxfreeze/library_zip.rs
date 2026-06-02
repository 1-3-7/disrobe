#![allow(
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_possible_truncation
)]

use std::path::{Path, PathBuf};

use disrobe_binfmt::extract::{ExtractionResult as BinfmtResult, extract_to_with_quota};
use disrobe_binfmt::{ContainerKind, ExtractionQuota as BinfmtQuota};

use crate::common::pyc::fingerprint;
use crate::common::quota::ExtractionQuota;
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct ExtractedEntry {
    pub name: String,
    pub disk_path: PathBuf,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
    pub python_version: Option<(u8, u8)>,
}

pub fn extract_all(zip_bytes: &[u8], out_dir: &Path) -> Result<Vec<ExtractedEntry>> {
    extract_all_with_quota(zip_bytes, out_dir, ExtractionQuota::default_safe())
}

pub fn extract_all_with_quota(
    zip_bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<Vec<ExtractedEntry>> {
    std::fs::create_dir_all(out_dir)?;
    let binfmt_quota: BinfmtQuota = bridge_quota(quota);
    let result: BinfmtResult =
        extract_to_with_quota(ContainerKind::Zip, zip_bytes, out_dir, binfmt_quota).map_err(
            |e: disrobe_binfmt::Error| match e {
                disrobe_binfmt::Error::Zip(s) => Error::Zip(s),
                disrobe_binfmt::Error::ZipEntry { name, reason } => Error::ZipEntry(name, reason),
                disrobe_binfmt::Error::UnsafeEntryPath(p) => Error::UnsafeEntryPath(p),
                disrobe_binfmt::Error::QuotaExceeded { entry, reason } => {
                    Error::QuotaExceeded { entry, reason }
                }
                disrobe_binfmt::Error::Io(io) => Error::Io(io),
                other => Error::Zip(other.to_string()),
            },
        )?;
    if let Some(first_violation) = result.integrity_violations.first() {
        return Err(Error::UnsafeEntryPath(first_violation.clone()));
    }
    let mut out: Vec<ExtractedEntry> = Vec::with_capacity(result.entries.len());
    for entry in &result.entries {
        let disk_path: PathBuf = entry
            .disk_path
            .clone()
            .unwrap_or_else(|| out_dir.join(&entry.name));
        let py_ver: Option<(u8, u8)> = if entry.name.ends_with(".pyc") {
            let body: Vec<u8> = std::fs::read(&disk_path)?;
            fingerprint(&body).map(|fp| (fp.python_major, fp.python_minor))
        } else {
            None
        };
        out.push(ExtractedEntry {
            name: entry.name.clone(),
            disk_path,
            uncompressed_size: entry.uncompressed_size,
            compressed_size: entry.compressed_size,
            python_version: py_ver,
        });
    }
    Ok(out)
}

const fn bridge_quota(quota: ExtractionQuota) -> BinfmtQuota {
    BinfmtQuota {
        max_entries: quota.max_entries,
        max_total_uncompressed: quota.max_total_uncompressed,
        max_per_entry_uncompressed: quota.max_per_entry_uncompressed,
        max_per_entry_ratio: quota.max_expansion_ratio,
        max_aggregate_ratio: u64::MAX,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn sanitize_check(name: &str) -> Result<String> {
        disrobe_binfmt::sanitize_entry_path(name).map_err(|e| Error::UnsafeEntryPath(e.to_string()))
    }

    #[test]
    fn sanitize_rejects_parent_escape() {
        assert!(sanitize_check("../etc/passwd").is_err());
        assert!(sanitize_check("subdir/../bad").is_err());
    }

    #[test]
    fn sanitize_passes_normal() {
        assert_eq!(sanitize_check("pkg/mod.pyc").unwrap(), "pkg/mod.pyc");
        assert_eq!(sanitize_check("pkg\\mod.pyc").unwrap(), "pkg/mod.pyc");
    }
}
