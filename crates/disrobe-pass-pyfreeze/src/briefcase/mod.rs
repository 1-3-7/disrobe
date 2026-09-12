pub mod layout;

use std::path::Path;

use crate::common::manifest::{EntryKind, EntryOrigin, EntryRecord, FreezerKind, FreezerManifest};
use crate::error::Result;

#[derive(Debug, Clone)]
pub struct BriefcaseExtraction {
    pub manifest: FreezerManifest,
    pub layout: layout::BriefcaseLayout,
    pub indexed_modules: Vec<EntryRecord>,
}

pub fn detect_and_extract(binary_path: &Path) -> Result<BriefcaseExtraction> {
    let layout: layout::BriefcaseLayout = layout::probe(binary_path)?;
    let mut manifest: FreezerManifest =
        FreezerManifest::new(FreezerKind::Briefcase, binary_path.display().to_string());
    manifest.interpreter_hint = layout
        .python_stdlib_dir
        .as_ref()
        .map(|p| p.display().to_string());

    let mut indexed: Vec<EntryRecord> = Vec::new();
    if let Some(ref app_dir) = layout.app_dir {
        for entry in layout::walk_python_sources(app_dir)? {
            let kind: EntryKind = classify(&entry.relative_name);
            let rec: EntryRecord = EntryRecord {
                name: entry.relative_name.clone(),
                kind,
                size: entry.size,
                compressed_size: None,
                python_major: None,
                python_minor: None,
                source_path: Some(entry.disk_path.display().to_string()),
                origin: EntryOrigin::SiblingFile,
            };
            indexed.push(rec.clone());
            manifest.push(rec);
        }
    }

    Ok(BriefcaseExtraction {
        manifest,
        layout,
        indexed_modules: indexed,
    })
}

#[must_use]
pub fn looks_like_briefcase(binary_path: &Path) -> bool {
    layout::probe(binary_path).is_ok()
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn classify(name: &str) -> EntryKind {
    let lower: String = name.to_ascii_lowercase();
    if lower.ends_with(".pyc") {
        EntryKind::PythonByteCode
    } else if lower.ends_with(".py") {
        EntryKind::PythonModule
    } else if lower.ends_with(".so") || lower.ends_with(".pyd") || lower.ends_with(".dll") {
        EntryKind::NativeExtension
    } else if lower.ends_with(".dist-info/metadata") || lower.ends_with(".dist-info/record") {
        EntryKind::Metadata
    } else {
        EntryKind::Resource
    }
}
