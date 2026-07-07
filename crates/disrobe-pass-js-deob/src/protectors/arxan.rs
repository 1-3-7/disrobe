use core::ops::Range;
use std::collections::BTreeSet;

use regex::Regex;

use super::{
    LegalStance, ProtectorDetection, ProtectorFamily, ProtectorOptions, ProtectorOutput,
    ProtectorStats,
};
use crate::error::{Error, Result};

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

pub const FAMILY: ProtectorFamily = ProtectorFamily::Arxan;
pub const LEGAL: LegalStance = LegalStance::AmberDetectOnly;

const MARKERS: &[(&str, &str)] = &[
    (r"(?i)digital\.ai", "digital-ai-banner"),
    (r"(?i)arxan", "arxan-banner"),
    (r"_ARXAN_", "arxan-runtime-token"),
    (r"__guard_[0-9a-f]{6,}", "arxan-guard-symbol"),
];

const PUBLIC_PATTERNS: &[(&str, &str)] = &[
    (
        r"(?s)/\*[^*]*(?:Digital\.ai|Arxan)[^*]*\*/",
        "digital-ai-banner-comment",
    ),
    (
        r"function\s+__guard_[0-9a-f]+\s*\(\s*\)\s*\{[^}]*atob\s*\(\s*['\x22][A-Za-z0-9+/=]{16,}['\x22]\s*\)[^}]*\}",
        "arxan-b64-checksum-guard-shape",
    ),
    (
        r"for\s*\(\s*var\s+__chk\s*=\s*0\s*;\s*__chk\s*<\s*[A-Za-z_$][\w$]*\.length\s*;\s*__chk\+\+\s*\)\s*\{[^}]*\^=[^}]*\}",
        "deterministic-checksum-loop",
    ),
    (
        r"if\s*\(\s*__arxan_integrity\s*\(\s*\)\s*!==?\s*0x[0-9a-fA-F]+\s*\)\s*\{[^}]*\}",
        "integrity-callout-constant-compare",
    ),
    (
        r"var\s+_ARXAN_[A-Za-z_$][\w$]*\s*=\s*[^;]+;?",
        "arxan-runtime-marker-var",
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
            confidence += 0.35;
        }
    }
    for (pat, label) in PUBLIC_PATTERNS {
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

pub fn deobfuscate(source: &str, opts: &ProtectorOptions) -> Result<ProtectorOutput> {
    let detection: Option<ProtectorDetection> = detect(source);
    let bytes_in: usize = source.len();
    if detection.is_none() {
        return Err(Error::NoFamilyMatched);
    }
    if !opts.i_have_authorization {
        return Err(Error::AuthorizationRequired { transform: "arxan" });
    }
    let mut stats: ProtectorStats = ProtectorStats::default();
    let mut current: String = source.to_owned();
    for (pat, label) in PUBLIC_PATTERNS {
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
    let bytes_out: usize = current.len();
    Ok(ProtectorOutput {
        source: current,
        bytes_in,
        bytes_out,
        family: FAMILY,
        legal_stance: LEGAL,
        stance_doc: LEGAL.stance_doc(),
        detection,
        stats,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn legal_stance_const_matches_family() {
        assert_eq!(LEGAL, FAMILY.legal_stance());
        assert!(LEGAL.allows_bypass_with_authorization());
        assert_eq!(LEGAL.stance_doc(), "docs/legal/digital-ai-arxan-stance.md");
    }

    #[test]
    fn detects_digital_ai_banner() {
        let src: &str = "/* (c) Digital.ai Application Protection */ var x = 1;";
        let det: ProtectorDetection = detect(src).expect("detected");
        assert_eq!(det.family, FAMILY);
    }

    #[test]
    fn detects_guard_symbol() {
        let src: &str = "function __guard_abc123def() { return 1; }";
        assert!(detect(src).is_some());
    }

    #[test]
    fn no_detect_on_clean_js() {
        let src: &str = "function foo() { return 1; }";
        assert!(detect(src).is_none());
    }

    #[test]
    fn strip_requires_authorization() {
        let src: &str = "/* Digital.ai */ var x = 1;";
        let err: Error = deobfuscate(src, &ProtectorOptions::default()).unwrap_err();
        assert!(matches!(err, Error::AuthorizationRequired { .. }));
    }

    #[test]
    fn strips_self_identifying_integrity_callout_on_synthetic_fixture() {
        let src: &str = "/* Digital.ai */ var x = 1; if (__arxan_integrity() !== 0xdeadbeef) { throw 'tamper'; } return x;";
        let opts: ProtectorOptions = ProtectorOptions {
            i_have_authorization: true,
        };
        let out: ProtectorOutput = deobfuscate(src, &opts).unwrap();
        assert!(!out.source.contains("__arxan_integrity"));
        assert!(out.stats.reversed >= 1);
    }
}
