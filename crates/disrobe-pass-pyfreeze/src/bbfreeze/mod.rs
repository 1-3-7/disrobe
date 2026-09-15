pub mod layout;

use std::path::{Path, PathBuf};

use crate::common::manifest::{EntryKind, EntryOrigin, EntryRecord, FreezerKind, FreezerManifest};
use crate::cxfreeze::library_zip::{self, ExtractedEntry};
use crate::error::Result;
use crate::{MAX_LIBRARY_ZIP_BYTES, read_file_bounded};

#[derive(Debug, Clone)]
pub struct BbfreezeExtraction {
    pub manifest: FreezerManifest,
    pub library_zip_path: PathBuf,
    pub python_dll: Option<PathBuf>,
    pub py_launcher: Option<PathBuf>,
    pub extracted: Vec<ExtractedEntry>,
}

pub fn detect_and_extract(binary_path: &Path, out_dir: &Path) -> Result<BbfreezeExtraction> {
    let layout: layout::BbfreezeLayout =
        layout::probe(binary_path).ok_or(crate::error::Error::UnknownFormat)?;
    let zip_bytes: Vec<u8> = read_file_bounded(&layout.library_zip, MAX_LIBRARY_ZIP_BYTES)?;
    let extracted: Vec<ExtractedEntry> = library_zip::extract_all(&zip_bytes, out_dir)?;

    let mut manifest: FreezerManifest =
        FreezerManifest::new(FreezerKind::Bbfreeze, binary_path.display().to_string());
    if let Some(name) = layout.python_dll_name.as_deref()
        && let Some((major, minor)) = parse_runtime_version(name)
    {
        manifest.python_major = Some(major);
        manifest.python_minor = Some(minor);
        manifest.interpreter_hint = Some(name.to_owned());
    }

    let mut primary: Option<String> = None;
    for ent in &extracted {
        if primary.is_none() && is_entry_point(&ent.name) {
            primary = Some(ent.name.clone());
        }
        let (maj, min): (u8, u8) = ent.python_version.unwrap_or((0, 0));
        if manifest.python_major.is_none() && maj != 0 {
            manifest.python_major = Some(maj);
            manifest.python_minor = Some(min);
        }
        manifest.push(EntryRecord {
            name: ent.name.clone(),
            kind: classify(&ent.name),
            size: ent.uncompressed_size,
            compressed_size: Some(ent.compressed_size),
            python_major: if maj == 0 { None } else { Some(maj) },
            python_minor: if maj == 0 { None } else { Some(min) },
            source_path: Some(ent.disk_path.display().to_string()),
            origin: EntryOrigin::LibraryZip,
        });
    }
    manifest.primary_module = primary;

    Ok(BbfreezeExtraction {
        manifest,
        library_zip_path: layout.library_zip,
        python_dll: layout.python_dll,
        py_launcher: layout.py_launcher,
        extracted,
    })
}

fn is_entry_point(name: &str) -> bool {
    name == "__main__.pyc"
        || name == "__main__.py"
        || name.ends_with("/__main__.pyc")
        || name.ends_with("/__main__.py")
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn classify(name: &str) -> EntryKind {
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

fn parse_runtime_version(name: &str) -> Option<(u8, u8)> {
    let lower: String = name.to_ascii_lowercase();
    let rest: &str = lower
        .strip_prefix("libpython")
        .or_else(|| lower.strip_prefix("python"))?;
    let trimmed: &str = rest
        .strip_suffix(".dll")
        .or_else(|| rest.split(".so").next())
        .unwrap_or(rest);
    if let Some((major_part, minor_part)) = trimmed.split_once('.') {
        let major: u8 = major_part.parse::<u8>().ok()?;
        let minor_digits: String = minor_part
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        return Some((major, minor_digits.parse::<u8>().ok()?));
    }
    let digits: String = trimmed.chars().take_while(char::is_ascii_digit).collect();
    match digits.len() {
        2 | 3 => Some((digits[..1].parse().ok()?, digits[1..].parse().ok()?)),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_windows_runtime_dll_version() {
        assert_eq!(parse_runtime_version("python27.dll"), Some((2, 7)));
        assert_eq!(parse_runtime_version("python312.dll"), Some((3, 12)));
        assert_eq!(parse_runtime_version("python34.DLL"), Some((3, 4)));
    }

    #[test]
    fn parses_unix_runtime_version() {
        assert_eq!(parse_runtime_version("libpython3.8.so.1.0"), Some((3, 8)));
        assert_eq!(parse_runtime_version("python3.11.so"), Some((3, 11)));
    }

    #[test]
    fn classifies_bytecode_and_native() {
        assert_eq!(classify("email/__init__.pyc"), EntryKind::PythonByteCode);
        assert_eq!(classify("_socket.pyd"), EntryKind::NativeExtension);
        assert_eq!(classify("data.txt"), EntryKind::Resource);
    }

    #[test]
    fn entry_point_recognized() {
        assert!(is_entry_point("__main__.pyc"));
        assert!(is_entry_point("pkg/__main__.py"));
        assert!(!is_entry_point("pkg/mod.pyc"));
    }
}
