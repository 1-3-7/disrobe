pub mod library;
pub mod overlay;
pub mod pe;
pub mod scriptinfo;

use std::path::{Path, PathBuf};

use crate::common::manifest::{EntryKind, EntryOrigin, EntryRecord, FreezerKind, FreezerManifest};
use crate::common::pyc::fingerprint;
use crate::common::zip_tail::is_likely_trailing_zip;
use crate::cxfreeze::library_zip::ExtractedEntry;
use crate::error::{Error, Result};
use crate::recover::{RecoveredModule, recover_bytecode, recover_raw_marshal};

pub use scriptinfo::ScriptInfo;

#[derive(Debug, Clone)]
pub struct Py2exeExtraction {
    pub manifest: FreezerManifest,
    pub script_resource_bytes: Vec<u8>,
    pub script_info: ScriptInfo,
    pub embedded_pyc: Vec<u8>,
    pub embedded_pyc_path: PathBuf,
    pub overlay_zip: Option<Vec<u8>>,
    pub library_zip_path: Option<PathBuf>,
    pub bundled_modules: Vec<ExtractedEntry>,
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

    let overlay: Option<Vec<u8>> = if is_likely_trailing_zip(binary_bytes) {
        Some(overlay::extract_overlay_zip(binary_bytes)?)
    } else {
        None
    };

    let mut manifest: FreezerManifest =
        FreezerManifest::new(FreezerKind::Py2exe, binary_path.display().to_string());
    let fp: Option<crate::common::pyc::PycFingerprint> = fingerprint(&info.marshalled_code);
    if let Some(fp) = fp {
        manifest.python_major = Some(fp.python_major);
        manifest.python_minor = Some(fp.python_minor);
    } else if let Some((major, minor)) = pe::sniff_python_version(binary_bytes) {
        manifest.python_major = Some(major);
        manifest.python_minor = Some(minor);
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

    let bundled: library::BundledModules =
        library::extract_bundled_modules(binary_path, overlay.as_deref(), out_dir)?;
    for ent in &bundled.entries {
        if manifest.python_major.is_none()
            && let Some((maj, min)) = ent.python_version
        {
            manifest.python_major = Some(maj);
            manifest.python_minor = Some(min);
        }
        let (maj, min): (u8, u8) = ent.python_version.unwrap_or((0, 0));
        let origin: EntryOrigin =
            if bundled.overlay_member_count > 0 && bundled.library_zip_path.is_none() {
                EntryOrigin::TrailingZip
            } else {
                EntryOrigin::LibraryZip
            };
        manifest.push(EntryRecord {
            name: ent.name.clone(),
            kind: classify_bundled(&ent.name),
            size: ent.uncompressed_size,
            compressed_size: Some(ent.compressed_size),
            python_major: if maj == 0 { None } else { Some(maj) },
            python_minor: if maj == 0 { None } else { Some(min) },
            source_path: Some(ent.disk_path.display().to_string()),
            origin,
        });
    }

    Ok(Py2exeExtraction {
        manifest,
        script_resource_bytes: resource,
        script_info: info,
        embedded_pyc: Vec::new(),
        embedded_pyc_path,
        overlay_zip: overlay,
        library_zip_path: bundled.library_zip_path,
        bundled_modules: bundled.entries,
    })
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn classify_bundled(name: &str) -> EntryKind {
    if name.ends_with(".pyc") || name.ends_with(".pyo") {
        EntryKind::PythonByteCode
    } else if name.ends_with(".py") {
        EntryKind::PythonModule
    } else if name.ends_with(".pyd") || name.ends_with(".so") || name.ends_with(".dll") {
        EntryKind::NativeExtension
    } else {
        EntryKind::Resource
    }
}

impl Py2exeExtraction {
    pub fn recover_main(&self, python_major: u8, python_minor: u8) -> Result<RecoveredModule> {
        let marshal: &[u8] = &self.script_info.marshalled_code;
        if fingerprint(marshal).is_some() {
            return recover_bytecode("__pythonscript__.pyc", marshal);
        }
        recover_raw_marshal("__pythonscript__", marshal, python_major, python_minor)
    }
}

#[allow(dead_code)]
pub(crate) const fn into_truncation_error(need: usize, got: usize) -> Error {
    Error::Py2exeScriptInfoTruncated { need, got }
}
