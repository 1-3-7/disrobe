pub mod signatures;

use std::path::{Path, PathBuf};

use crate::common::manifest::{EntryKind, EntryOrigin, EntryRecord, FreezerKind, FreezerManifest};
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct PyOxidizerExtraction {
    pub manifest: FreezerManifest,
    pub python_dll_hint: Option<String>,
    pub markers_found: Vec<String>,
    pub config_blob_path: Option<PathBuf>,
}

pub fn detect_and_extract(
    bytes: &[u8],
    source: &Path,
    out_dir: &Path,
) -> Result<PyOxidizerExtraction> {
    std::fs::create_dir_all(out_dir)?;
    let markers: Vec<String> = signatures::scan(bytes);
    if !signatures::is_present(&markers) {
        return Err(Error::PyOxidizerConfigMissing);
    }
    let (python_major, python_minor, python_dll_hint): (Option<u8>, Option<u8>, Option<String>) =
        signatures::infer_python_version(bytes);

    let blob: Option<&[u8]> = signatures::extract_resources_blob(bytes);
    let config_blob_path: Option<PathBuf> = if let Some(slice) = blob {
        let blob_path: PathBuf = out_dir.join("pyoxidizer_resources.blob");
        std::fs::write(&blob_path, slice)?;
        Some(blob_path)
    } else {
        None
    };

    let mut manifest: FreezerManifest =
        FreezerManifest::new(FreezerKind::PyOxidizer, source.display().to_string());
    manifest.python_major = python_major;
    manifest.python_minor = python_minor;
    manifest.interpreter_hint.clone_from(&python_dll_hint);
    if let Some(ref blob_path) = config_blob_path {
        manifest.push(EntryRecord {
            name: "pyoxidizer_resources.blob".to_owned(),
            kind: EntryKind::Resource,
            size: bytes.len() as u64,
            compressed_size: None,
            python_major,
            python_minor,
            source_path: Some(blob_path.display().to_string()),
            origin: EntryOrigin::Other,
        });
    }

    Ok(PyOxidizerExtraction {
        manifest,
        python_dll_hint,
        markers_found: markers,
        config_blob_path,
    })
}

#[must_use]
pub fn looks_like_pyoxidizer(bytes: &[u8]) -> bool {
    let m: Vec<String> = signatures::scan(bytes);
    signatures::is_present(&m)
}
