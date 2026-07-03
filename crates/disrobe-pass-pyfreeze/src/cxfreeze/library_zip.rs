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
use crate::{MAX_RECOVERY_FILE_BYTES, read_file_bounded};

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
            let body: Vec<u8> = read_file_bounded(&disk_path, MAX_RECOVERY_FILE_BYTES)?;
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
        max_aggregate_ratio: quota.max_aggregate_ratio,
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

    #[test]
    fn bridge_quota_arms_finite_aggregate_ratio() {
        let bridged: BinfmtQuota = bridge_quota(ExtractionQuota::default_safe());
        assert!(
            bridged.max_aggregate_ratio < u64::MAX,
            "the aggregate zip-bomb cap must not be disabled"
        );
        assert!(
            bridged.max_aggregate_ratio <= bridged.max_per_entry_ratio,
            "the aggregate cap must be at least as strict as the per-entry ratio"
        );
        let unrestricted: BinfmtQuota = bridge_quota(ExtractionQuota::unrestricted());
        assert_eq!(
            unrestricted.max_aggregate_ratio,
            u64::MAX,
            "the explicit unrestricted quota must still disable the cap"
        );
    }

    fn build_deflated_zip(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        let mut writer: zip::ZipWriter<std::io::Cursor<Vec<u8>>> =
            zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options: SimpleFileOptions =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in entries {
            writer.start_file(*name, options).expect("start file");
            writer.write_all(body).expect("write body");
        }
        writer.finish().expect("finish zip").into_inner()
    }

    #[test]
    fn extract_rejects_aggregate_zip_bomb_within_bounded_time() {
        let big: Vec<u8> = vec![0u8; 4 * 1024 * 1024];
        let entries: [(&str, Vec<u8>); 4] = [
            ("a.pyc", big.clone()),
            ("b.pyc", big.clone()),
            ("c.pyc", big.clone()),
            ("d.pyc", big),
        ];
        let zip_bytes: Vec<u8> = build_deflated_zip(&entries);
        let tmp: std::path::PathBuf = std::env::temp_dir().join(format!(
            "disrobe-cxfreeze-aggbomb-{}-{}",
            std::process::id(),
            zip_bytes.len()
        ));
        let strict: ExtractionQuota = ExtractionQuota {
            max_expansion_ratio: u64::MAX,
            max_aggregate_ratio: 4,
            ..ExtractionQuota::default_safe()
        };
        let start: std::time::Instant = std::time::Instant::now();
        let result: Result<Vec<ExtractedEntry>> = extract_all_with_quota(&zip_bytes, &tmp, strict);
        let elapsed: std::time::Duration = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "aggregate-bomb rejection must stay bounded; took {elapsed:?}"
        );
        let err: Error = result.expect_err("an aggregate zip bomb must be rejected");
        assert!(
            matches!(err, Error::QuotaExceeded { .. }),
            "aggregate ratio breach must surface QuotaExceeded, got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn extract_passes_normal_zip_under_aggregate_cap() {
        let entries: [(&str, Vec<u8>); 2] = [
            ("pkg/__init__.pyc", b"short module body bytes".to_vec()),
            ("pkg/mod.pyc", b"another small module payload".to_vec()),
        ];
        let zip_bytes: Vec<u8> = build_deflated_zip(&entries);
        let tmp: std::path::PathBuf = std::env::temp_dir().join(format!(
            "disrobe-cxfreeze-ok-{}-{}",
            std::process::id(),
            zip_bytes.len()
        ));
        let out: Vec<ExtractedEntry> =
            extract_all_with_quota(&zip_bytes, &tmp, ExtractionQuota::default_safe())
                .expect("a normal cx_Freeze zip must still extract under the armed aggregate cap");
        assert_eq!(out.len(), 2, "both members must extract: {out:?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
