use std::path::Path;

use crate::briefcase::layout::probe as briefcase_probe;
use crate::common::manifest::FreezerKind;
use crate::common::shebang;
use crate::common::zip_tail;
use crate::cxfreeze::layout::could_be_cxfreeze;
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
    let mut reasons: Vec<String> = Vec::new();

    if let Some(path) = source_path {
        if could_be_cxfreeze(path) {
            reasons.push(
                "sibling lib/library.zip + frozen_application_license.txt detected".to_owned(),
            );
            return Detection {
                kind: FreezerKind::CxFreeze,
                confidence: 0.95,
                reasons,
            };
        }
        if briefcase_probe(path).is_ok() {
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

    if looks_like_pe(bytes)
        && bytes
            .windows(b"PYTHONSCRIPT".len())
            .any(|w| w == b"PYTHONSCRIPT")
    {
        reasons.push("PE resource name PYTHONSCRIPT present".to_owned());
        return Detection {
            kind: FreezerKind::Py2exe,
            confidence: 0.92,
            reasons,
        };
    }

    if looks_like_pyoxidizer(bytes) {
        reasons.push("pyembed/PyOxidizer runtime markers present".to_owned());
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
    let trailing_zip: bool = zip_tail::is_likely_trailing_zip(bytes);

    if has_python_shebang
        && trailing_zip
        && let Ok(info) = zip_tail::locate(bytes)
    {
        let zip: &[u8] = &bytes[info.archive_start_offset..];
        let cd_slice: &[u8] = central_directory_slice(zip, &info);
        if contains_marker(zip, cd_slice, b"PEX-INFO") {
            reasons.push("python shebang + trailing zip + PEX-INFO marker".to_owned());
            return Detection {
                kind: FreezerKind::Pex,
                confidence: 0.93,
                reasons,
            };
        }
        if contains_marker(zip, cd_slice, b"_bootstrap/") {
            reasons.push("python shebang + trailing zip + _bootstrap marker".to_owned());
            return Detection {
                kind: FreezerKind::Shiv,
                confidence: 0.9,
                reasons,
            };
        }
    }

    Detection {
        kind: FreezerKind::Unknown,
        confidence: 0.0,
        reasons: vec![
            "no cx_freeze / py2exe / shiv / pex / pyoxidizer / briefcase marker matched".to_owned(),
        ],
    }
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
