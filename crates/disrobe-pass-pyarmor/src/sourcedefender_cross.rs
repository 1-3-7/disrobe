use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourcedefenderCrossKind {
    PyeExtension,
    PyeMagic,
    LoaderImport,
    DecoratorMarker,
    BotwoodHeader,
    InlinedEnvelope,
}

impl SourcedefenderCrossKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::PyeExtension => "pye-extension",
            Self::PyeMagic => "pye-magic",
            Self::LoaderImport => "loader-import",
            Self::DecoratorMarker => "decorator-marker",
            Self::BotwoodHeader => "botwood-header",
            Self::InlinedEnvelope => "inlined-envelope",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossoverFinding {
    pub kind: SourcedefenderCrossKind,
    pub offset: Option<usize>,
    pub evidence: String,
}

const PYE_FILE_MAGIC: &[u8] = b"@__SOURCE_DEFENDER__";
const BOTWOOD_HEADER: &[u8] = b"SourceDefender";
const LOADER_IMPORT_STRINGS: &[&[u8]] = &[
    b"from sourcedefender",
    b"import sourcedefender",
    b"sourcedefender.protected",
];
const DECORATOR_STRINGS: &[&[u8]] = &[
    b"@sourcedefender",
    b"sd_decrypt(",
    b"sourcedefender_decrypt",
];
const INLINED_ENVELOPE_STRINGS: &[&[u8]] = &[b"sd_load_module", b"SDExecModule", b".pye\x00"];

#[must_use]
pub fn detect_sourcedefender_cross(
    wrapper_text: &str,
    wrapper_path: Option<&Path>,
    payload: &[u8],
) -> Vec<CrossoverFinding> {
    let mut findings: Vec<CrossoverFinding> = Vec::new();

    if let Some(p) = wrapper_path
        && has_pye_extension(p)
    {
        findings.push(CrossoverFinding {
            kind: SourcedefenderCrossKind::PyeExtension,
            offset: None,
            evidence: p.display().to_string(),
        });
    }

    let wrapper_bytes: &[u8] = wrapper_text.as_bytes();
    if let Some(offset) = find_subslice(wrapper_bytes, PYE_FILE_MAGIC) {
        findings.push(CrossoverFinding {
            kind: SourcedefenderCrossKind::PyeMagic,
            offset: Some(offset),
            evidence: "@__SOURCE_DEFENDER__ magic in wrapper text".to_owned(),
        });
    }
    if let Some(offset) = find_subslice(payload, PYE_FILE_MAGIC) {
        findings.push(CrossoverFinding {
            kind: SourcedefenderCrossKind::PyeMagic,
            offset: Some(offset),
            evidence: "@__SOURCE_DEFENDER__ magic inside PyArmor payload".to_owned(),
        });
    }
    if let Some(offset) = find_subslice(wrapper_bytes, BOTWOOD_HEADER) {
        findings.push(CrossoverFinding {
            kind: SourcedefenderCrossKind::BotwoodHeader,
            offset: Some(offset),
            evidence: "SourceDefender header string in wrapper text".to_owned(),
        });
    }
    if let Some(offset) = find_subslice(payload, BOTWOOD_HEADER) {
        findings.push(CrossoverFinding {
            kind: SourcedefenderCrossKind::BotwoodHeader,
            offset: Some(offset),
            evidence: "SourceDefender header string inside PyArmor payload".to_owned(),
        });
    }

    for marker in LOADER_IMPORT_STRINGS {
        if let Some(offset) = find_subslice(wrapper_bytes, marker) {
            findings.push(CrossoverFinding {
                kind: SourcedefenderCrossKind::LoaderImport,
                offset: Some(offset),
                evidence: utf8_or_hex(marker),
            });
        }
    }

    for marker in DECORATOR_STRINGS {
        if let Some(offset) = find_subslice(wrapper_bytes, marker) {
            findings.push(CrossoverFinding {
                kind: SourcedefenderCrossKind::DecoratorMarker,
                offset: Some(offset),
                evidence: utf8_or_hex(marker),
            });
        }
    }

    for marker in INLINED_ENVELOPE_STRINGS {
        if let Some(offset) = find_subslice(payload, marker) {
            findings.push(CrossoverFinding {
                kind: SourcedefenderCrossKind::InlinedEnvelope,
                offset: Some(offset),
                evidence: utf8_or_hex(marker),
            });
        }
    }

    findings
}

fn has_pye_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("pye"))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn utf8_or_hex(bytes: &[u8]) -> String {
    core::str::from_utf8(bytes).map_or_else(
        |_| {
            const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
            let mut encoded: String = String::with_capacity(bytes.len() * 2);
            for byte in bytes.iter().copied() {
                encoded.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
                encoded.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
            }
            encoded
        },
        str::to_owned,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn no_crossover_when_input_is_clean_pyarmor() {
        let wrapper: &str = "from pyarmor_runtime_000000 import __pyarmor__\n__pyarmor__(__name__, __file__, b'PY009070')";
        let findings: Vec<CrossoverFinding> =
            detect_sourcedefender_cross(wrapper, None, b"clean payload");
        assert!(findings.is_empty());
    }

    #[test]
    fn pye_extension_triggers_finding() {
        let path: PathBuf = PathBuf::from("evidence/sample.pye");
        let findings: Vec<CrossoverFinding> = detect_sourcedefender_cross("", Some(&path), &[]);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.kind, SourcedefenderCrossKind::PyeExtension))
        );
    }

    #[test]
    fn loader_import_in_wrapper_text() {
        let wrapper: &str = "from sourcedefender import sd_load_module\nimport whatever";
        let findings: Vec<CrossoverFinding> = detect_sourcedefender_cross(wrapper, None, b"");
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.kind, SourcedefenderCrossKind::LoaderImport))
        );
    }

    #[test]
    fn pye_magic_inside_payload_detected() {
        let mut payload: Vec<u8> = vec![0u8; 256];
        let magic: &[u8; 20] = b"@__SOURCE_DEFENDER__";
        payload[64..64 + magic.len()].copy_from_slice(magic);
        let findings: Vec<CrossoverFinding> = detect_sourcedefender_cross("", None, &payload);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.kind, SourcedefenderCrossKind::PyeMagic))
        );
    }

    #[test]
    fn label_strings_are_stable() {
        assert_eq!(
            SourcedefenderCrossKind::PyeExtension.label(),
            "pye-extension"
        );
        assert_eq!(
            SourcedefenderCrossKind::LoaderImport.label(),
            "loader-import"
        );
        assert_eq!(
            SourcedefenderCrossKind::BotwoodHeader.label(),
            "botwood-header"
        );
    }
}
