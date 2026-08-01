use std::io::Cursor;
use std::path::Path;

use crate::bbfreeze;
use crate::briefcase::layout::probe as briefcase_probe;
use crate::common::manifest::FreezerKind;
use crate::common::pyc::fingerprint;
use crate::common::shebang;
use crate::common::zip_tail;
use crate::cxfreeze::layout::could_be_cxfreeze;
use crate::debug::{dbg_hex, dbg_kv, dbg_section};
use crate::py2exe::pe::looks_like_pe;
use crate::pyoxidizer::looks_like_pyoxidizer;

#[derive(Debug, Clone)]
pub struct Detection {
    pub kind: FreezerKind,
    pub confidence: f32,
    pub reasons: Vec<String>,
}

#[must_use]
pub fn detect_bytes(bytes: &[u8], source_path: Option<&Path>) -> Detection {
    dbg_section("pyfreeze detect");
    dbg_kv("input-len", || bytes.len().to_string());
    dbg_hex("input-magic", bytes, 8);
    dbg_kv("source-path", || {
        source_path.map_or_else(|| "<none>".to_owned(), |p: &Path| p.display().to_string())
    });
    let mut reasons: Vec<String> = Vec::new();

    if looks_like_pe(bytes)
        && bytes
            .windows(b"PYTHONSCRIPT".len())
            .any(|w| w == b"PYTHONSCRIPT")
    {
        dbg_kv("classify", || {
            "Py2exe (PE resource name PYTHONSCRIPT)".to_owned()
        });
        reasons.push("PE resource name PYTHONSCRIPT present".to_owned());
        return Detection {
            kind: FreezerKind::Py2exe,
            confidence: 0.92,
            reasons,
        };
    }

    if let Some(path) = source_path {
        if could_be_cxfreeze(path) {
            dbg_kv("classify", || {
                "CxFreeze (sibling lib/library.zip + frozen_application_license.txt)".to_owned()
            });
            reasons.push(
                "sibling lib/library.zip + frozen_application_license.txt detected".to_owned(),
            );
            return Detection {
                kind: FreezerKind::CxFreeze,
                confidence: 0.95,
                reasons,
            };
        }
        if let Some(bb) = bbfreeze::layout::probe(path) {
            dbg_kv("classify", || {
                "Bbfreeze (sibling library.zip + pythonNN.dll, no PYTHONSCRIPT resource)".to_owned()
            });
            reasons.push(format!(
                "sibling library.zip + {} detected (bbfreeze runtime layout)",
                bb.python_dll_name.as_deref().unwrap_or("pythonNN.dll")
            ));
            return Detection {
                kind: FreezerKind::Bbfreeze,
                confidence: 0.82,
                reasons,
            };
        }
        if briefcase_probe(path).is_ok() {
            dbg_kv("classify", || {
                "Briefcase (sibling app_packages/ or python-stdlib/ or briefcase.toml)".to_owned()
            });
            reasons.push(
                "sibling app_packages/ or python-stdlib/ or briefcase.toml detected".to_owned(),
            );
            return Detection {
                kind: FreezerKind::Briefcase,
                confidence: 0.9,
                reasons,
            };
        }
    }

    if looks_like_pyoxidizer(bytes) {
        dbg_kv("classify", || {
            "PyOxidizer (experimental, unvalidated pyembed runtime markers)".to_owned()
        });
        reasons.push(
            "experimental, unvalidated PyOxidizer classification from pyembed runtime markers"
                .to_owned(),
        );
        return Detection {
            kind: FreezerKind::PyOxidizer,
            confidence: 0.88,
            reasons,
        };
    }

    let shebang_hdr: Option<shebang::Shebang> = shebang::parse(bytes);
    let has_python_shebang: bool = shebang_hdr
        .as_ref()
        .is_some_and(|s| shebang::looks_like_python_runner(&s.line));
    let path_is_zipapp: bool = source_path.is_some_and(path_has_zipapp_extension);
    let trailing_zip: bool = zip_tail::is_likely_trailing_zip(bytes);
    dbg_kv("shebang-runner", || has_python_shebang.to_string());
    dbg_kv("zipapp-extension", || path_is_zipapp.to_string());
    dbg_kv("trailing-zip", || trailing_zip.to_string());

    if trailing_zip && let Ok(info) = zip_tail::locate(bytes) {
        let zip: &[u8] = &bytes[info.archive_start_offset..];
        let cd_slice: &[u8] = central_directory_slice(zip, &info);
        if contains_marker(zip, cd_slice, b"PEX-INFO") {
            dbg_kv("classify", || "Pex (trailing zip + PEX-INFO)".to_owned());
            reasons.push("trailing zip + PEX-INFO marker".to_owned());
            return Detection {
                kind: FreezerKind::Pex,
                confidence: 0.93,
                reasons,
            };
        }
        if contains_marker(zip, cd_slice, b"_bootstrap/") {
            dbg_kv("classify", || "Shiv (trailing zip + _bootstrap)".to_owned());
            reasons.push("trailing zip + _bootstrap marker".to_owned());
            return Detection {
                kind: FreezerKind::Shiv,
                confidence: 0.9,
                reasons,
            };
        }
        let markers: ZipPythonMarkers = zip_python_markers(zip);
        if markers.has_main || ((has_python_shebang || path_is_zipapp) && markers.has_python_entry)
        {
            dbg_kv("classify", || {
                "Zipapp (trailing zip python entries)".to_owned()
            });
            reasons.push("trailing zip with Python module entries".to_owned());
            return Detection {
                kind: FreezerKind::Zipapp,
                confidence: if markers.has_main { 0.84 } else { 0.76 },
                reasons,
            };
        }
    }

    if let Some(fp) = fingerprint(bytes)
        && bytes.len() >= fp.header_len
    {
        dbg_kv("classify", || "Pyc (known CPython magic)".to_owned());
        reasons.push(format!(
            "known CPython pyc magic 0x{magic:08x} for {major}.{minor}",
            magic = fp.magic,
            major = fp.python_major,
            minor = fp.python_minor
        ));
        return Detection {
            kind: FreezerKind::Pyc,
            confidence: 0.72,
            reasons,
        };
    }

    dbg_kv("classify", || {
        "Unknown (no freezer marker matched)".to_owned()
    });
    Detection {
        kind: FreezerKind::Unknown,
        confidence: 0.0,
        reasons: vec![
            "no cx_freeze / py2exe / shiv / pex / PyOxidizer (experimental, unvalidated) / briefcase marker matched"
                .to_owned(),
        ],
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ZipPythonMarkers {
    has_main: bool,
    has_python_entry: bool,
}

fn zip_python_markers(zip: &[u8]) -> ZipPythonMarkers {
    const MAX_MARKER_ENTRIES: usize = 65_536;
    let mut archive: zip::ZipArchive<Cursor<&[u8]>> = match zip::ZipArchive::new(Cursor::new(zip)) {
        Ok(a) => a,
        Err(_) => return ZipPythonMarkers::default(),
    };
    let count: usize = archive.len().min(MAX_MARKER_ENTRIES);
    let mut markers: ZipPythonMarkers = ZipPythonMarkers::default();
    for i in 0..count {
        let file: zip::read::ZipFile<'_> = match archive.by_index(i) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let name: &str = file.name();
        if name == "__main__.py" || name == "__main__.pyc" {
            markers.has_main = true;
            markers.has_python_entry = true;
            return markers;
        }
        let ext: Option<&str> = Path::new(name).extension().and_then(|e| e.to_str());
        if ext.is_some_and(|e: &str| e.eq_ignore_ascii_case("py") || e.eq_ignore_ascii_case("pyc"))
        {
            markers.has_python_entry = true;
        }
    }
    markers
}

fn path_has_zipapp_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e: &str| e.eq_ignore_ascii_case("pyz") || e.eq_ignore_ascii_case("pyzw"))
}

fn central_directory_slice<'a>(zip: &'a [u8], info: &zip_tail::ZipTailInfo) -> &'a [u8] {
    let cd_start: usize = info.central_dir_offset;
    let cd_end: usize = cd_start.saturating_add(info.central_dir_size);
    if cd_start <= zip.len() && cd_end <= zip.len() && cd_start < cd_end {
        &zip[cd_start..cd_end]
    } else {
        &[]
    }
}

fn contains_marker(zip: &[u8], cd_slice: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || zip.len() < needle.len() {
        return false;
    }
    if !cd_slice.is_empty() && cd_slice.windows(needle.len()).any(|w: &[u8]| w == needle) {
        return true;
    }
    zip.windows(needle.len()).any(|w: &[u8]| w == needle)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    use zip::write::SimpleFileOptions;

    const PYTHON_SHEBANG: &[u8] = b"#!/usr/bin/env python3\n";

    fn build_zip(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zip_buf: Vec<u8> = Vec::new();
        {
            let mut writer: zip::ZipWriter<Cursor<&mut Vec<u8>>> =
                zip::ZipWriter::new(Cursor::new(&mut zip_buf));
            let opts: SimpleFileOptions =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for (name, body) in members {
                writer.start_file(*name, opts).expect("start member");
                writer.write_all(body).expect("write member");
            }
            writer.finish().expect("finish zip");
        }
        zip_buf
    }

    #[test]
    fn detects_stdlib_zipapp_by_main_module() {
        let zip: Vec<u8> = build_zip(&[("__main__.py", b"print('ok')\n")]);
        let mut bytes: Vec<u8> = Vec::with_capacity(PYTHON_SHEBANG.len() + zip.len());
        bytes.extend_from_slice(PYTHON_SHEBANG);
        bytes.extend_from_slice(&zip);
        let det: Detection = detect_bytes(&bytes, Some(Path::new("hello.pyz")));
        assert_eq!(det.kind, FreezerKind::Zipapp, "got: {det:?}");
    }

    #[test]
    fn detects_zipapp_extension_without_shebang() {
        let bytes: Vec<u8> = build_zip(&[("pkg/mod.py", b"VALUE = 7\n")]);
        let det: Detection = detect_bytes(&bytes, Some(Path::new("bundle.pyz")));
        assert_eq!(det.kind, FreezerKind::Zipapp, "got: {det:?}");
    }

    #[test]
    fn detects_raw_pyc_magic_from_shared_table() {
        let magic: u32 = disrobe_py_marshal::magic_for(disrobe_py_marshal::PyVersion::PY315)
            .expect("known magic");
        let mut bytes: Vec<u8> = magic.to_le_bytes().to_vec();
        bytes.resize(16, 0);
        let det: Detection = detect_bytes(&bytes, Some(Path::new("mod.pyc")));
        assert_eq!(det.kind, FreezerKind::Pyc, "got: {det:?}");
        assert!(
            det.reasons
                .iter()
                .any(|reason: &String| reason.contains("3.15")),
            "pyc detection reason must include the resolved Python version; got {det:?}"
        );
    }
}
