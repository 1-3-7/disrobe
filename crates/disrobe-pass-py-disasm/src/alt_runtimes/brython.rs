use disrobe_pass_js_deob::{Detection as JsDetection, detect as detect_js};
use serde::{Deserialize, Serialize};

use crate::alt_runtimes::{AltRuntimeError, Result};

const BRYTHON_RUNTIME_MARKER: &str = "__BRYTHON__";
const BRYTHON_MODULE_MARKER: &str = "$B.imported";
const BRYTHON_AST_MARKER: &str = "$B.modules";
const BRYTHON_INIT_FN: &str = "brython(";
const HEAD_SCAN_LIMIT: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrythonModule {
    pub markers: Vec<String>,
    pub js_detection_family: String,
    pub js_detection_confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsDeobHandoff {
    pub family: String,
    pub confidence_pct: u32,
    pub brython_markers: Vec<String>,
    pub source_len: u32,
}

pub fn parse(bytes: &[u8]) -> Result<BrythonModule> {
    if !detect(bytes) {
        return Err(AltRuntimeError::NotDetected("brython"));
    }
    let markers: Vec<String> = scan_markers(bytes);
    let detection: JsDetection = detect_js(bytes);
    Ok(BrythonModule {
        markers,
        js_detection_family: format!("{:?}", detection.family),
        js_detection_confidence: detection.confidence,
    })
}

pub fn handoff(bytes: &[u8]) -> Result<JsDeobHandoff> {
    if !detect(bytes) {
        return Err(AltRuntimeError::NotDetected("brython"));
    }
    let detection: JsDetection = detect_js(bytes);
    let markers: Vec<String> = scan_markers(bytes);
    let confidence_pct: u32 = scale_confidence(detection.confidence);
    Ok(JsDeobHandoff {
        family: format!("{:?}", detection.family),
        confidence_pct,
        brython_markers: markers,
        source_len: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
    })
}

#[must_use]
pub fn detect(bytes: &[u8]) -> bool {
    let head: &[u8] = if bytes.len() > HEAD_SCAN_LIMIT {
        &bytes[..HEAD_SCAN_LIMIT]
    } else {
        bytes
    };
    has_marker(head, BRYTHON_RUNTIME_MARKER.as_bytes())
        || has_marker(head, BRYTHON_MODULE_MARKER.as_bytes())
        || has_marker(head, BRYTHON_AST_MARKER.as_bytes())
        || has_marker(head, BRYTHON_INIT_FN.as_bytes())
}

fn scan_markers(bytes: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let head: &[u8] = if bytes.len() > HEAD_SCAN_LIMIT {
        &bytes[..HEAD_SCAN_LIMIT]
    } else {
        bytes
    };
    for needle in [
        BRYTHON_RUNTIME_MARKER,
        BRYTHON_MODULE_MARKER,
        BRYTHON_AST_MARKER,
        BRYTHON_INIT_FN,
    ] {
        if has_marker(head, needle.as_bytes()) {
            out.push(needle.to_owned());
        }
    }
    out
}

fn has_marker(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn scale_confidence(confidence: f32) -> u32 {
    let scaled: f32 = (confidence * 100.0_f32).clamp(0.0_f32, 100.0_f32);
    scaled.round() as u32
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const BRYTHON_SAMPLE: &[u8] =
        b"var $B = __BRYTHON__; $B.modules['hello'] = {}; $B.imported['hello'] = true;";

    #[test]
    fn detect_finds_brython_marker() {
        assert!(detect(BRYTHON_SAMPLE));
    }

    #[test]
    fn detect_rejects_non_brython_js() {
        let bytes: &[u8] = b"const x = 1; console.log(x);";
        assert!(!detect(bytes));
    }

    #[test]
    fn parse_collects_markers() {
        let module: BrythonModule = parse(BRYTHON_SAMPLE).expect("parse brython");
        assert!(module.markers.contains(&BRYTHON_RUNTIME_MARKER.to_owned()));
    }

    #[test]
    fn handoff_emits_js_family() {
        let h: JsDeobHandoff = handoff(BRYTHON_SAMPLE).expect("handoff");
        assert!(!h.family.is_empty());
        assert!(!h.brython_markers.is_empty());
    }

    #[test]
    fn parse_negative_returns_not_detected() {
        let bytes: &[u8] = b"alert(1);";
        let err: AltRuntimeError = parse(bytes).expect_err("must fail");
        assert!(matches!(err, AltRuntimeError::NotDetected(_)));
    }
}
