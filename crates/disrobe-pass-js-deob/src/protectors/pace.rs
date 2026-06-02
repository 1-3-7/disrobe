use std::collections::BTreeSet;

use regex::Regex;

use super::{
    LegalStance, ProtectorDetection, ProtectorFamily, ProtectorOptions, ProtectorOutput,
    ProtectorStats,
};
use crate::error::{Error, Result};

pub const FAMILY: ProtectorFamily = ProtectorFamily::Pace;
pub const LEGAL: LegalStance = LegalStance::AmberDetectNoBypass;

const MARKERS: &[(&str, &str)] = &[
    (r"(?i)pace\s+anti[\s-]piracy", "pace-anti-piracy-banner"),
    (r"(?i)pace\s+fusion", "pace-fusion-banner"),
    (r"(?i)ilok", "ilok-token"),
    (r"__PACE__", "pace-runtime-token"),
    (r"_PACE_FUSION_", "pace-fusion-runtime-token"),
];

const SELF_CHECK_PATTERNS: &[(&str, &str)] = &[
    (
        r"setInterval\s*\(\s*function\s*\(\s*\)\s*\{[^}]*__PACE__[^}]*\}\s*,\s*\d+\s*\)",
        "pace-runtime-self-check-interval",
    ),
    (
        r"if\s*\(\s*window\s*\[\s*['\x22]__PACE__['\x22]\s*\]\s*===?\s*undefined\s*\)",
        "pace-runtime-presence-check",
    ),
];

#[must_use]
pub fn detect(source: &str) -> Option<ProtectorDetection> {
    let mut markers: BTreeSet<String> = BTreeSet::new();
    let mut confidence: f32 = 0.0;
    for (pat, label) in MARKERS {
        let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(pat) else {
            continue;
        };
        if re.is_match(source) {
            markers.insert((*label).to_owned());
            confidence += 0.40;
        }
    }
    for (pat, label) in SELF_CHECK_PATTERNS {
        let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(pat) else {
            continue;
        };
        if re.is_match(source) {
            markers.insert((*label).to_owned());
            confidence += 0.30;
        }
    }
    if confidence <= 0.0 {
        return None;
    }
    let confidence_clamped: f32 = confidence.min(0.99_f32);
    let markers_vec: Vec<String> = markers.into_iter().collect();
    Some(ProtectorDetection::new(
        FAMILY,
        confidence_clamped,
        markers_vec,
    ))
}

pub const fn deobfuscate(_source: &str, _opts: &ProtectorOptions) -> Result<ProtectorOutput> {
    Err(Error::PaceBypassUnsupported {
        stance_doc: LEGAL.stance_doc(),
    })
}

#[must_use]
pub fn detect_only_report(source: &str) -> ProtectorOutput {
    let detection: Option<ProtectorDetection> = detect(source);
    let bytes_in: usize = source.len();
    let matched: usize = detection
        .as_ref()
        .map_or(0, |d: &ProtectorDetection| d.markers.len());
    let stats: ProtectorStats = ProtectorStats {
        matched,
        reversed: 0,
        skipped: matched,
        errors: vec!["DR-JS-PACE-DetectOnly: bypass unsupported by design".to_owned()],
    };
    ProtectorOutput {
        source: source.to_owned(),
        bytes_in,
        bytes_out: bytes_in,
        family: FAMILY,
        legal_stance: LEGAL,
        stance_doc: LEGAL.stance_doc(),
        detection,
        stats,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn legal_stance_const_matches_family() {
        assert_eq!(LEGAL, FAMILY.legal_stance());
        assert!(!LEGAL.allows_bypass_with_authorization());
        assert_eq!(LEGAL.stance_doc(), "docs/legal/pace-js-stance.md");
    }

    #[test]
    fn detects_pace_banner() {
        let src: &str = "/* PACE Anti-Piracy Fusion */ var x = 1;";
        let det: ProtectorDetection = detect(src).expect("detected");
        assert_eq!(det.family, FAMILY);
        assert!(!det.markers.is_empty());
    }

    #[test]
    fn detects_runtime_token() {
        let src: &str = "if (window['__PACE__'] === undefined) { location.reload(); }";
        let det: ProtectorDetection = detect(src).expect("detected");
        assert!(det.confidence >= 0.30);
    }

    #[test]
    fn no_detect_on_clean_js() {
        let src: &str = "const x = 1;";
        assert!(detect(src).is_none());
    }

    #[test]
    fn bypass_rejected_without_authorization() {
        let src: &str = "/* PACE Anti-Piracy */ var x = 1;";
        let err: Error = deobfuscate(src, &ProtectorOptions::default()).unwrap_err();
        match err {
            Error::PaceBypassUnsupported { stance_doc } => {
                assert_eq!(stance_doc, "docs/legal/pace-js-stance.md");
            }
            other => panic!("expected PaceBypassUnsupported, got {other:?}"),
        }
    }

    #[test]
    fn bypass_rejected_even_with_authorization() {
        let src: &str = "/* PACE Anti-Piracy */ var x = 1;";
        let opts: ProtectorOptions = ProtectorOptions {
            i_have_authorization: true,
        };
        let err: Error = deobfuscate(src, &opts).unwrap_err();
        assert!(matches!(err, Error::PaceBypassUnsupported { .. }));
    }

    #[test]
    fn detect_only_report_returns_detection_with_skip_message() {
        let src: &str = "/* PACE Anti-Piracy */ var x = 1;";
        let out: ProtectorOutput = detect_only_report(src);
        assert!(out.detection.is_some());
        assert!(
            out.stats
                .errors
                .iter()
                .any(|e: &String| e.contains("DR-JS-PACE-DetectOnly"))
        );
        assert_eq!(out.stats.reversed, 0);
    }
}
