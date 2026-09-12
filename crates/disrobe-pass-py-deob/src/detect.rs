use std::sync::LazyLock;

use disrobe_core::byte_search;
use regex::Regex;
use serde::Serialize;

use crate::debug::dbg_kv;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Family {
    Hyperion,
    KramerSpecterBerserker,
    BlankObf,
    Pyfuscator,
    GenericDropper,
    PyObfuscator,
    Opy,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub family: Family,
    pub confidence: f32,
    pub markers: Vec<String>,
}

const HYPERION_MARKER: &str = "__obfuscator__ = 'Hyperion'";
const HYPERION_AUTHOR: &str = "billythegoat356";
const KRAMER_BINARY_MARKER: &[u8] = b"\r\r\n";
const BLANK_OBF_MARKER: &str = "BlankOBF";

#[must_use]
pub fn detect(source: &[u8]) -> Detection {
    let head_slice: &[u8] = &source[..source.len().min(8192)];
    let text_head: &str = std::str::from_utf8(head_slice).unwrap_or("");
    let mut markers: Vec<String> = Vec::new();
    let mut family: Family = Family::Unknown;
    let mut confidence: f32 = 0.0f32;

    if text_head.contains(HYPERION_MARKER) {
        family = Family::Hyperion;
        confidence = 0.99;
        markers.push("hyperion-banner".to_owned());
    } else if text_head.contains(HYPERION_AUTHOR) && text_head.contains("Power") {
        family = Family::Hyperion;
        confidence = 0.7;
        markers.push("hyperion-author".to_owned());
    } else if source.len() > 16
        && byte_search::contains(&source[..16.min(source.len())], KRAMER_BINARY_MARKER)
    {
        family = Family::KramerSpecterBerserker;
        confidence = 0.85;
        markers.push("crrn-pyc-magic".to_owned());
    } else if text_head.contains(BLANK_OBF_MARKER) {
        family = Family::BlankObf;
        confidence = 0.85;
        markers.push("blankobf-marker".to_owned());
    } else if dropper_matches(text_head) {
        let mods: Vec<String> = extract_dropper_modules(text_head);
        if mods.contains(&"base64".to_owned()) && mods.contains(&"zlib".to_owned()) {
            family = Family::GenericDropper;
            confidence = 0.7;
            markers.push("generic-dropper-base64-zlib".to_owned());
        } else if mods.contains(&"base64".to_owned()) {
            family = Family::Pyfuscator;
            confidence = 0.55;
            markers.push("pyfuscator-pattern".to_owned());
        }
    }

    if family == Family::Unknown && text_head.contains("__pyobfuscator__") {
        family = Family::PyObfuscator;
        confidence = 0.6;
        markers.push("pyobfuscator-marker".to_owned());
    }

    dbg_kv("family-detect", || {
        format!(
            "{family:?} confidence={confidence:.2} markers=[{m}]",
            m = markers.join(",")
        )
    });

    Detection {
        family,
        confidence,
        markers,
    }
}

const DROPPER_PATTERN: &str = r#"exec\s*\(\s*__import__\s*\(\s*(?:'|")([a-z0-9_]+)(?:'|")\s*\)\s*\.\s*([a-z0-9_]+)\s*\(\s*__import__\s*\(\s*(?:'|")([a-z0-9_]+)(?:'|")\s*\)\s*\.\s*([a-z0-9_]+)\s*\("#;

static DROPPER_REGEX: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(DROPPER_PATTERN).ok());

#[inline]
fn dropper_matches(text: &str) -> bool {
    DROPPER_REGEX.as_ref().is_some_and(|r| r.is_match(text))
}

fn extract_dropper_modules(text: &str) -> Vec<String> {
    let mut mods: Vec<String> = Vec::new();
    let Some(re): Option<&Regex> = DROPPER_REGEX.as_ref() else {
        return mods;
    };
    let Some(caps): Option<regex::Captures<'_>> = re.captures(text) else {
        return mods;
    };
    if let Some(m) = caps.get(1) {
        mods.push(m.as_str().to_owned());
    }
    if let Some(m) = caps.get(3) {
        mods.push(m.as_str().to_owned());
    }
    mods
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_hyperion_banner() {
        let src: &[u8] = b"from builtins import *\n__obfuscator__ = 'Hyperion'\n";
        let det: Detection = detect(src);
        assert_eq!(det.family, Family::Hyperion);
        assert!(det.confidence > 0.9);
    }

    #[test]
    fn detects_pyobfuscator_marker() {
        let src: &[u8] = b"__pyobfuscator__ = '1.0'\nprint('x')\n";
        let det: Detection = detect(src);
        assert_eq!(det.family, Family::PyObfuscator);
        assert!(det.markers.iter().any(|m| m.contains("pyobfuscator")));
    }

    #[test]
    fn detects_blank_obf_marker() {
        let src: &[u8] = b"# BlankOBF v1\nimport sys\n";
        let det: Detection = detect(src);
        assert_eq!(det.family, Family::BlankObf);
    }

    #[test]
    fn alternation_regex_check() {
        let src: &str = "exec(__import__('zlib').decompress(__import__('base64').b85decode(";
        assert!(
            dropper_matches(src),
            "alternation regex should match canonical dropper line"
        );
    }

    #[test]
    fn dropper_regex_compiles_and_matches() {
        let src: &str =
            "exec(__import__('zlib').decompress(__import__('base64').b85decode(b'cafebabe')))";
        let mods: Vec<String> = extract_dropper_modules(src);
        assert!(
            dropper_matches(src),
            "regex must match canonical dropper line; mods={mods:?}"
        );
        assert!(mods.contains(&"zlib".to_owned()));
        assert!(mods.contains(&"base64".to_owned()));
    }

    #[test]
    fn unknown_for_plain_python() {
        let src: &[u8] = b"def foo():\n    return 1\n";
        let det: Detection = detect(src);
        assert_eq!(det.family, Family::Unknown);
    }

    #[test]
    fn detects_kramer_marker_in_binary() {
        let mut src: Vec<u8> = vec![0u8; 32];
        src[0..3].copy_from_slice(b"\r\r\n");
        let det: Detection = detect(&src);
        assert_eq!(det.family, Family::KramerSpecterBerserker);
    }

    #[test]
    fn empty_needle_search_is_defined_instead_of_panicking() {
        assert_eq!(byte_search::find(b"\r\r\npayload", b""), None);
        assert!(!byte_search::contains(b"\r\r\npayload", b""));
        assert_eq!(byte_search::find(b"", b""), None);
        assert!(!byte_search::contains(b"", b""));
    }

    #[test]
    fn detect_survives_degenerate_inputs() {
        for src in [b"".as_slice(), b"\r".as_slice(), b"\r\r\n".as_slice()] {
            let det: Detection = detect(src);
            assert_eq!(det.family, Family::Unknown);
        }
    }
}
