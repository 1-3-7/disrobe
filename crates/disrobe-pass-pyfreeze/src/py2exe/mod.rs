pub mod overlay;
pub mod pe;
pub mod scriptinfo;

use std::path::{Path, PathBuf};

use crate::common::manifest::{EntryKind, EntryOrigin, EntryRecord, FreezerKind, FreezerManifest};
use crate::common::pyc::fingerprint;
use crate::error::{Error, Result};

pub use scriptinfo::ScriptInfo;

#[derive(Debug, Clone)]
pub struct Py2exeExtraction {
    pub manifest: FreezerManifest,
    pub script_resource_bytes: Vec<u8>,
    pub script_info: ScriptInfo,
    pub embedded_pyc: Vec<u8>,
    pub embedded_pyc_path: PathBuf,
    pub overlay_zip: Option<Vec<u8>>,
}

pub fn detect_and_extract(
    binary_bytes: &[u8],
    binary_path: &Path,
    out_dir: &Path,
) -> Result<Py2exeExtraction> {
    std::fs::create_dir_all(out_dir)?;
    let resource: Vec<u8> = pe::extract_pythonscript_resource(binary_bytes)?;
    let info: ScriptInfo = scriptinfo::parse(&resource)?;

    let embedded_pyc_path: PathBuf = out_dir.join("__pythonscript__.pyc");
    std::fs::write(&embedded_pyc_path, &info.marshalled_code)?;

    let overlay: Option<Vec<u8>> = overlay::extract_overlay_zip(binary_bytes).ok();

    let mut manifest: FreezerManifest =
        FreezerManifest::new(FreezerKind::Py2exe, binary_path.display().to_string());
    let fp: Option<crate::common::pyc::PycFingerprint> = fingerprint(&info.marshalled_code);
    if let Some(fp) = fp {
        manifest.python_major = Some(fp.python_major);
        manifest.python_minor = Some(fp.python_minor);
    }
    manifest.push(EntryRecord {
        name: "__pythonscript__.pyc".to_owned(),
        kind: EntryKind::PythonByteCode,
        size: info.marshalled_code.len() as u64,
        compressed_size: None,
        python_major: fp.map(|f| f.python_major),
        python_minor: fp.map(|f| f.python_minor),
        source_path: Some(embedded_pyc_path.display().to_string()),
        origin: EntryOrigin::PeResource,
    });
    manifest.primary_module = Some("__pythonscript__.pyc".to_owned());

    Ok(Py2exeExtraction {
        manifest,
        script_resource_bytes: resource,
        script_info: info,
        embedded_pyc: Vec::new(),
        embedded_pyc_path,
        overlay_zip: overlay,
    })
}

#[allow(dead_code)]
pub(crate) const fn into_truncation_error(need: usize, got: usize) -> Error {
    Error::Py2exeScriptInfoTruncated { need, got }
}
