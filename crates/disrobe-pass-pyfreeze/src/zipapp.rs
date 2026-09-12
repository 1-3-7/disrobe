use std::io::Cursor;
use std::path::{Path, PathBuf};

use zip::ZipArchive;

use crate::common::manifest::{EntryKind, EntryOrigin, EntryRecord, FreezerKind, FreezerManifest};
use crate::common::pyc::{PycFingerprint, fingerprint};
use crate::common::quota::{
    ExtractionQuota, QuotaGuard, admit_charged_entry, default_quota, next_entry_uncompressed_limit,
    reject_declared_entry_over_cap,
};
use crate::common::shebang::parse as parse_shebang;
use crate::common::zip_tail::locate;
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct ZipappExtraction {
    pub manifest: FreezerManifest,
    pub extracted: Vec<ExtractedEntry>,
}

#[derive(Debug, Clone)]
pub struct ExtractedEntry {
    pub name: String,
    pub disk_path: PathBuf,
}

pub fn detect_and_extract(bytes: &[u8], source: &Path, out_dir: &Path) -> Result<ZipappExtraction> {
    detect_and_extract_with_quota(bytes, source, out_dir, default_quota())
}

pub fn detect_and_extract_with_quota(
    bytes: &[u8],
    source: &Path,
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ZipappExtraction> {
    std::fs::create_dir_all(out_dir)?;
    let info: crate::common::zip_tail::ZipTailInfo = locate(bytes)?;
    let zip_slice: &[u8] = &bytes[info.archive_start_offset..];
    let mut archive: ZipArchive<Cursor<&[u8]>> =
        ZipArchive::new(Cursor::new(zip_slice)).map_err(|e| Error::Zip(e.to_string()))?;

    let shebang: Option<crate::common::shebang::Shebang> = parse_shebang(bytes);
    let mut manifest: FreezerManifest =
        FreezerManifest::new(FreezerKind::Zipapp, source.display().to_string());
    manifest.interpreter_hint = shebang.as_ref().and_then(|s| s.interpreter_hint.clone());

    let mut extracted: Vec<ExtractedEntry> = Vec::new();
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut saw_python_entry: bool = false;
    for i in 0..archive.len() {
        let mut file: zip::read::ZipFile<'_> =
            archive.by_index(i).map_err(|e| Error::Zip(e.to_string()))?;
        if file.is_dir() {
            continue;
        }
        let safe: String = sanitize(file.name())?;
        let declared_size: u64 = file.size();
        let compressed_size: u64 = file.compressed_size();
        reject_declared_entry_over_cap(quota, &safe, declared_size)?;
        let read_limit: u64 = next_entry_uncompressed_limit(quota, &guard);
        let buf: Vec<u8> =
            crate::common::read_bounded::read_to_vec_limited(&mut file, declared_size, read_limit)
                .map_err(|e| Error::ZipEntry(safe.clone(), e.to_string()))?;
        let actual_size: u64 = u64::try_from(buf.len()).map_err(|_| Error::QuotaExceeded {
            entry: safe.clone(),
            reason: "actual uncompressed size exceeds u64".to_owned(),
        })?;
        admit_charged_entry(&mut guard, &safe, actual_size, compressed_size)?;
        let disk_path: PathBuf = out_dir.join(&safe);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &buf)?;

        let kind: EntryKind = classify(&safe);
        if matches!(kind, EntryKind::PythonModule | EntryKind::PythonByteCode) {
            saw_python_entry = true;
        }
        if manifest.primary_module.is_none() && (safe == "__main__.py" || safe == "__main__.pyc") {
            manifest.primary_module = Some(safe.clone());
        }
        let fp: Option<PycFingerprint> = if matches!(kind, EntryKind::PythonByteCode) {
            fingerprint(&buf)
        } else {
            None
        };
        if manifest.python_major.is_none()
            && let Some(version) = fp
        {
            manifest.python_major = Some(version.python_major);
            manifest.python_minor = Some(version.python_minor);
        }
        manifest.push(EntryRecord {
            name: safe.clone(),
            kind,
            size: declared_size,
            compressed_size: Some(compressed_size),
            python_major: fp.map(|f: PycFingerprint| f.python_major),
            python_minor: fp.map(|f: PycFingerprint| f.python_minor),
            source_path: Some(disk_path.display().to_string()),
            origin: EntryOrigin::TrailingZip,
        });
        extracted.push(ExtractedEntry {
            name: safe,
            disk_path,
        });
    }
    if !saw_python_entry {
        return Err(Error::ZipappPythonEntryMissing);
    }

    Ok(ZipappExtraction {
        manifest,
        extracted,
    })
}

fn classify(name: &str) -> EntryKind {
    let ext: Option<&str> = Path::new(name).extension().and_then(|e| e.to_str());
    if ext_is(ext, "pyc") {
        EntryKind::PythonByteCode
    } else if ext_is(ext, "py") {
        EntryKind::PythonModule
    } else if is_native_ext(ext) {
        EntryKind::NativeExtension
    } else if ext_is(ext, "whl") {
        EntryKind::Wheel
    } else if is_dist_info_metadata(name) {
        EntryKind::Metadata
    } else {
        EntryKind::Resource
    }
}

fn ext_is(ext: Option<&str>, needle: &str) -> bool {
    ext.is_some_and(|e: &str| e.eq_ignore_ascii_case(needle))
}

fn is_native_ext(ext: Option<&str>) -> bool {
    const NATIVE_EXTS: [&str; 3] = ["pyd", "so", "dll"];
    ext.is_some_and(|e: &str| {
        NATIVE_EXTS
            .iter()
            .any(|needle: &&str| e.eq_ignore_ascii_case(needle))
    })
}

fn is_dist_info_metadata(name: &str) -> bool {
    let normalized: String = name.replace('\\', "/");
    let Some((parent, file_name)): Option<(&str, &str)> = normalized.rsplit_once('/') else {
        return false;
    };
    file_name.eq_ignore_ascii_case("METADATA")
        && parent
            .as_bytes()
            .get(parent.len().saturating_sub(".dist-info".len())..)
            .is_some_and(|suffix: &[u8]| suffix.eq_ignore_ascii_case(b".dist-info"))
}

fn sanitize(name: &str) -> Result<String> {
    let trimmed: String = name.replace('\\', "/");
    if trimmed
        .split('/')
        .any(|c: &str| c == ".." || c.contains(':'))
    {
        return Err(Error::UnsafeEntryPath(name.to_owned()));
    }
    let cleaned: String = trimmed
        .split('/')
        .filter(|c: &&str| !c.is_empty() && *c != ".")
        .collect::<Vec<_>>()
        .join("/");
    if cleaned.is_empty() {
        return Err(Error::UnsafeEntryPath(name.to_owned()));
    }
    Ok(cleaned)
}
