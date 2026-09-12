#![allow(
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_possible_truncation
)]

use std::path::{Path, PathBuf};

use disrobe_binfmt::ContainerKind;
use disrobe_binfmt::extract::{ExtractionResult as BinfmtResult, extract_to_with_quota};

use crate::common::pyc::fingerprint;
use crate::common::quota::{ExtractionQuota, default_quota};
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
    extract_all_with_quota(zip_bytes, out_dir, default_quota())
}

pub fn extract_all_with_quota(
    zip_bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<Vec<ExtractedEntry>> {
    std::fs::create_dir_all(out_dir)?;
    let result: BinfmtResult =
        extract_to_with_quota(ContainerKind::Zip, zip_bytes, out_dir, quota)?;
    if let Some(error) = result
        .integrity_violations
        .iter()
        .find_map(|violation: &String| quota_refusal(violation))
    {
        return Err(error);
    }
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

fn quota_refusal(violation: &str) -> Option<Error> {
    const PREFIX: &str = "DR-BINFMT-0009: extraction quota exceeded on entry `";
    let (_, detail): (&str, &str) = violation.split_once(PREFIX)?;
    let (entry, reason): (&str, &str) = detail.split_once("`: ")?;
    (!entry.is_empty() && !reason.is_empty()).then(|| Error::QuotaExceeded {
        entry: entry.to_owned(),
        reason: reason.to_owned(),
    })
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
    fn default_quota_arms_finite_aggregate_ratio() {
        let default: ExtractionQuota = default_quota();
        assert!(
            default.max_aggregate_ratio < u64::MAX,
            "the aggregate zip-bomb cap must not be disabled"
        );
        assert!(
            default.max_aggregate_ratio <= default.max_per_entry_ratio,
            "the aggregate cap must be at least as strict as the per-entry ratio"
        );
        let unrestricted: ExtractionQuota = ExtractionQuota::unrestricted();
        assert_eq!(
            unrestricted.max_aggregate_ratio,
            u64::MAX,
            "the explicit unrestricted quota must still disable the cap"
        );
    }

    #[test]
    fn recorded_refusals_preserve_quota_and_path_error_kinds() {
        let quota: Error = quota_refusal(
            "zip-quota `a.pyc`: DR-BINFMT-0009: extraction quota exceeded on entry `a.pyc`: aggregate expansion ratio 12 exceeds cap 4",
        )
        .expect("parse the typed binfmt quota diagnostic");
        assert!(
            matches!(quota, Error::QuotaExceeded { entry, reason } if entry == "a.pyc" && reason == "aggregate expansion ratio 12 exceeds cap 4")
        );
        assert!(quota_refusal("zip-path `../a.pyc`: parent traversal").is_none());
        assert!(quota_refusal("DR-BINFMT-0009: truncated").is_none());
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
        let purpose: String = format!(
            "disrobe-cxfreeze-aggbomb-{}-{}",
            std::process::id(),
            zip_bytes.len()
        );
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
        let tmp: std::path::PathBuf = scratch.path().to_path_buf();
        let strict: ExtractionQuota = ExtractionQuota {
            max_per_entry_ratio: u64::MAX,
            max_aggregate_ratio: 4,
            ..default_quota()
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
    }

    #[test]
    fn extract_passes_normal_zip_under_aggregate_cap() {
        let entries: [(&str, Vec<u8>); 2] = [
            ("pkg/__init__.pyc", b"short module body bytes".to_vec()),
            ("pkg/mod.pyc", b"another small module payload".to_vec()),
        ];
        let zip_bytes: Vec<u8> = build_deflated_zip(&entries);
        let purpose: String = format!(
            "disrobe-cxfreeze-ok-{}-{}",
            std::process::id(),
            zip_bytes.len()
        );
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
        let tmp: std::path::PathBuf = scratch.path().to_path_buf();
        let out: Vec<ExtractedEntry> = extract_all_with_quota(&zip_bytes, &tmp, default_quota())
            .expect("a normal cx_Freeze zip must still extract under the armed aggregate cap");
        assert_eq!(out.len(), 2, "both members must extract: {out:?}");
    }
}
