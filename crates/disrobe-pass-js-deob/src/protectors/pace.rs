//! PACE JS / Fusion family detection and static guard-marker stripping.

use core::ops::Range;
use std::collections::BTreeSet;

use regex::Regex;

use super::{
    LegalStance, ProtectorDetection, ProtectorFamily, ProtectorOptions, ProtectorOutput,
    ProtectorStats,
};
use crate::error::{Error, Result};

pub const FAMILY: ProtectorFamily = ProtectorFamily::Pace;
pub const LEGAL: LegalStance = LegalStance::AmberDetectOnly;
pub const STANCE_DOC: &str = "docs/legal/pace-js-stance.md";

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
    (
        r"_PACE_FUSION_\s*\.\s*expected",
        "pace-fusion-expected-token",
    ),
];

const STRIP_PATTERNS: &[(&str, &str)] = &[
    (
        r"(?s)/\*[^*]*(?:PACE\s+Anti[\s-]Piracy|PACE\s+Fusion|iLok)[^*]*\*/",
        "pace-banner-comment",
    ),
    (
        r#"(?s)if\s*\(\s*window\s*\[\s*['"]__PACE__['"]\s*\]\s*===?\s*undefined\s*\)\s*\{\s*location\.reload\s*\(\s*\)\s*;?\s*\}\s*;?"#,
        "pace-runtime-presence-check",
    ),
    (
        r"(?s)setInterval\s*\(\s*function\s*\(\s*\)\s*\{(?:[^{}]|\{[^{}]*\})*(?:__PACE__|_PACE_FUSION_)(?:[^{}]|\{[^{}]*\})*\}\s*,\s*\d+\s*\)\s*;?",
        "pace-runtime-self-check-interval",
    ),
    (
        r"(?s)var\s+_PACE_FUSION_\s*=\s*\{(?:[^{}]|\{[^{}]*\})*\}\s*;?",
        "pace-fusion-static-config",
    ),
    (
        r#"var\s+ilok_token\s*=\s*['"][^'"]*['"]\s*;?"#,
        "pace-ilok-static-token",
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
    Some(ProtectorDetection {
        family: FAMILY,
        legal_stance: LEGAL,
        stance_doc: STANCE_DOC,
        confidence: confidence_clamped,
        markers: markers_vec,
    })
}

fn splice_blank(source: &str, ranges: &mut [Range<usize>]) -> (String, usize) {
    if ranges.is_empty() {
        return (source.to_owned(), 0usize);
    }
    ranges.sort_by_key(|r: &Range<usize>| r.start);
    let mut out: String = String::with_capacity(source.len());
    let mut cursor: usize = 0usize;
    let mut applied: usize = 0usize;
    let bytes_total: usize = source.len();
    for r in ranges.iter() {
        if r.start < cursor || r.end > bytes_total {
            continue;
        }
        out.push_str(&source[cursor..r.start]);
        cursor = r.end;
        applied = applied.saturating_add(1usize);
    }
    out.push_str(&source[cursor..]);
    (out, applied)
}

pub fn deobfuscate(source: &str, opts: &ProtectorOptions) -> Result<ProtectorOutput> {
    let detection: Option<ProtectorDetection> = detect(source);
    let bytes_in: usize = source.len();
    if detection.is_none() {
        return Err(Error::NoFamilyMatched);
    }
    if !opts.i_have_authorization {
        return Err(Error::AuthorizationRequired { transform: "pace" });
    }
    let mut stats: ProtectorStats = ProtectorStats::default();
    let mut current: String = source.to_owned();
    for (pat, label) in STRIP_PATTERNS {
        let Ok(re): core::result::Result<Regex, regex::Error> = Regex::new(pat) else {
            stats.errors.push(format!("compile fail: {label}"));
            continue;
        };
        let mut edits: Vec<Range<usize>> = Vec::new();
        for m in re.find_iter(&current) {
            stats.matched = stats.matched.saturating_add(1usize);
            edits.push(m.range());
        }
        if !edits.is_empty() {
            let (rewritten, applied): (String, usize) = splice_blank(&current, &mut edits);
            current = rewritten;
            stats.reversed = stats.reversed.saturating_add(applied);
        }
    }
    if stats.reversed == 0usize {
        return Err(Error::PaceUnsupportedPattern {
            stance_doc: STANCE_DOC,
        });
    }
    let bytes_out: usize = current.len();
    Ok(ProtectorOutput {
        source: current,
        bytes_in,
        bytes_out,
        family: FAMILY,
        legal_stance: LEGAL,
        stance_doc: STANCE_DOC,
        detection,
        stats,
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
        errors: vec!["DR-JS-PACE-UnsupportedPattern: no static guard pattern stripped".to_owned()],
    };
    ProtectorOutput {
        source: source.to_owned(),
        bytes_in,
        bytes_out: bytes_in,
        family: FAMILY,
        legal_stance: LEGAL,
        stance_doc: STANCE_DOC,
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
        assert!(LEGAL.allows_bypass_with_authorization());
        assert_eq!(STANCE_DOC, "docs/legal/pace-js-stance.md");
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
    fn strip_requires_authorization() {
        let src: &str = "/* PACE Anti-Piracy */ var x = 1;";
        let err: Error = deobfuscate(src, &ProtectorOptions::default()).unwrap_err();
        assert!(matches!(err, Error::AuthorizationRequired { .. }));
    }

    #[test]
    fn strips_self_identifying_guard_marker_on_synthetic_fixture_with_authorization() {
        let src: &str = "if (window['__PACE__'] === undefined) { location.reload(); }\nvar x = 1;";
        let opts: ProtectorOptions = ProtectorOptions {
            i_have_authorization: true,
        };
        let out: ProtectorOutput = deobfuscate(src, &opts).unwrap();
        assert!(!out.source.contains("__PACE__"));
        assert!(out.source.contains("var x = 1"));
        assert_eq!(out.stats.reversed, 1usize);
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
                .any(|e: &String| e.contains("DR-JS-PACE-UnsupportedPattern"))
        );
        assert_eq!(out.stats.reversed, 0);
    }
}
