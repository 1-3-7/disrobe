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

#[derive(Debug)]
struct SpanPattern {
    pattern: &'static str,
    label: &'static str,
    span_requires: Option<&'static str>,
}

const SPAN_PATTERNS: &[SpanPattern] = &[
    SpanPattern {
        pattern: r"(?s)/\*.*?\*/",
        label: "digital-ai-banner-comment",
        span_requires: Some(r"(?i)digital\.ai|arxan"),
    },
    SpanPattern {
        pattern: r"var\s+_ARXAN_[A-Za-z_$][\w$]*\s*=\s*[^;]+;?",
        label: "arxan-runtime-marker-var",
        span_requires: None,
    },
];

#[derive(Debug)]
struct BlockPattern {
    head: &'static str,
    label: &'static str,
    body_requires: Option<&'static str>,
}

const BLOCK_PATTERNS: &[BlockPattern] = &[
    BlockPattern {
        head: r"function\s+__guard_[0-9a-f]+\s*\(\s*\)\s*\{",
        label: "arxan-b64-checksum-guard-shape",
        body_requires: Some(r"atob\s*\(\s*['\x22][A-Za-z0-9+/=]{16,}['\x22]\s*\)"),
    },
    BlockPattern {
        head: r"for\s*\(\s*var\s+__chk\s*=\s*0\s*;\s*__chk\s*<\s*[A-Za-z_$][\w$]*\.length\s*;\s*__chk\+\+\s*\)\s*\{",
        label: "deterministic-checksum-loop",
        body_requires: Some(r"\^="),
    },
    BlockPattern {
        head: r"if\s*\(\s*__arxan_integrity\s*\(\s*\)\s*!==?\s*0x[0-9a-fA-F]+\s*\)\s*\{",
        label: "integrity-callout-constant-compare",
        body_requires: None,
    },
];

fn quoted_end(bytes: &[u8], open: usize) -> Option<usize> {
    let quote: u8 = *bytes.get(open)?;
    let mut i: usize = open.checked_add(1)?;
    while let Some(&b) = bytes.get(i) {
        if b == b'\\' {
            i = i.checked_add(2)?;
            continue;
        }
        if b == quote {
            return i.checked_add(1);
        }
        i = i.checked_add(1)?;
    }
    None
}

fn line_comment_end(bytes: &[u8], open: usize) -> usize {
    let mut i: usize = open.saturating_add(2);
    while let Some(&b) = bytes.get(i) {
        if b == b'\n' {
            return i.saturating_add(1);
        }
        i = i.saturating_add(1);
    }
    bytes.len()
}

fn block_comment_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut i: usize = open.checked_add(2)?;
    while let Some(&b) = bytes.get(i) {
        if b == b'*' && bytes.get(i.checked_add(1)?) == Some(&b'/') {
            return i.checked_add(2);
        }
        i = i.checked_add(1)?;
    }
    None
}

fn balanced_block_end(source: &str, open_brace: usize) -> Option<usize> {
    let bytes: &[u8] = source.as_bytes();
    if bytes.get(open_brace) != Some(&b'{') {
        return None;
    }
    let mut depth: usize = 1usize;
    let mut i: usize = open_brace.checked_add(1)?;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'\'' | b'"' | b'`' => i = quoted_end(bytes, i)?,
            b'/' => match bytes.get(i.saturating_add(1)) {
                Some(&b'/') => i = line_comment_end(bytes, i),
                Some(&b'*') => i = block_comment_end(bytes, i)?,
                _ => i = i.checked_add(1)?,
            },
            b'{' => {
                depth = depth.checked_add(1)?;
                i = i.checked_add(1)?;
            }
            b'}' => {
                depth = depth.checked_sub(1)?;
                i = i.checked_add(1)?;
                if depth == 0usize {
                    return Some(i);
                }
            }
            _ => i = i.checked_add(1)?,
        }
    }
    None
}

fn requirement_holds(pattern: Option<&'static str>, text: &str) -> bool {
    pattern.is_none_or(|pat: &'static str| Regex::new(pat).is_ok_and(|re: Regex| re.is_match(text)))
}

fn span_hits(
    source: &str,
    pattern: &SpanPattern,
) -> core::result::Result<Vec<Range<usize>>, String> {
    let re: Regex =
        Regex::new(pattern.pattern).map_err(|e: regex::Error| format!("{}: {e}", pattern.label))?;
    let mut hits: Vec<Range<usize>> = Vec::new();
    for m in re.find_iter(source) {
        if requirement_holds(pattern.span_requires, m.as_str()) {
            hits.push(m.range());
        }
    }
    Ok(hits)
}

fn block_hits(
    source: &str,
    pattern: &BlockPattern,
) -> core::result::Result<Vec<Range<usize>>, String> {
    let re: Regex =
        Regex::new(pattern.head).map_err(|e: regex::Error| format!("{}: {e}", pattern.label))?;
    let mut hits: Vec<Range<usize>> = Vec::new();
    for m in re.find_iter(source) {
        let open_brace: usize = m.end().saturating_sub(1usize);
        let Some(end): Option<usize> = balanced_block_end(source, open_brace) else {
            continue;
        };
        let Some(body): Option<&str> = source.get(m.end()..end.saturating_sub(1usize)) else {
            continue;
        };
        if requirement_holds(pattern.body_requires, body) {
            hits.push(m.start()..end);
        }
    }
    Ok(hits)
}

fn documented_labels(source: &str) -> BTreeSet<String> {
    let mut labels: BTreeSet<String> = BTreeSet::new();
    for pattern in SPAN_PATTERNS {
        if span_hits(source, pattern).is_ok_and(|h: Vec<Range<usize>>| !h.is_empty()) {
            labels.insert(pattern.label.to_owned());
        }
    }
    for pattern in BLOCK_PATTERNS {
        if block_hits(source, pattern).is_ok_and(|h: Vec<Range<usize>>| !h.is_empty()) {
            labels.insert(pattern.label.to_owned());
        }
    }
    labels
}

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
    for label in documented_labels(source) {
        markers.insert(label);
        confidence += 0.30;
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
    for pattern in SPAN_PATTERNS {
        match span_hits(&current, pattern) {
            Err(message) => stats.errors.push(format!("compile fail: {message}")),
            Ok(mut edits) => {
                stats.matched = stats.matched.saturating_add(edits.len());
                if !edits.is_empty() {
                    let (rewritten, applied): (String, usize) = splice_blank(&current, &mut edits);
                    current = rewritten;
                    stats.reversed = stats.reversed.saturating_add(applied);
                }
            }
        }
    }
    for pattern in BLOCK_PATTERNS {
        match block_hits(&current, pattern) {
            Err(message) => stats.errors.push(format!("compile fail: {message}")),
            Ok(mut edits) => {
                stats.matched = stats.matched.saturating_add(edits.len());
                if !edits.is_empty() {
                    let (rewritten, applied): (String, usize) = splice_blank(&current, &mut edits);
                    current = rewritten;
                    stats.reversed = stats.reversed.saturating_add(applied);
                }
            }
        }
    }
    let bytes_out: usize = current.len();
    Ok(ProtectorOutput {
        source: current,
        bytes_in,
        bytes_out,
        family: FAMILY,
        legal_stance: LEGAL,
        stance_doc: FAMILY.stance_doc(),
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
        assert_eq!(FAMILY.stance_doc(), "docs/legal/digital-ai-arxan-stance.md");
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

    #[test]
    fn banner_comment_carrying_a_star_is_still_removed() {
        let src: &str = "/* (c) Digital.ai * Application Protection */ var x = 1;";
        let opts: ProtectorOptions = ProtectorOptions {
            i_have_authorization: true,
        };
        let out: ProtectorOutput = deobfuscate(src, &opts).unwrap();
        assert_eq!(out.source.trim(), "var x = 1;");
    }

    #[test]
    fn unrelated_block_comment_survives_the_strip() {
        let src: &str = "/* Digital.ai */ /* keep me */ var x = 1;";
        let opts: ProtectorOptions = ProtectorOptions {
            i_have_authorization: true,
        };
        let out: ProtectorOutput = deobfuscate(src, &opts).unwrap();
        assert!(out.source.contains("/* keep me */"));
        assert!(!out.source.contains("Digital.ai"));
    }

    #[test]
    fn unbalanced_guard_block_is_left_alone_rather_than_half_removed() {
        let src: &str = "/* Digital.ai */ if (__arxan_integrity() !== 0xdeadbeef) { throw 'x';";
        let opts: ProtectorOptions = ProtectorOptions {
            i_have_authorization: true,
        };
        let out: ProtectorOutput = deobfuscate(src, &opts).unwrap();
        assert!(out.source.contains("__arxan_integrity"));
    }

    #[test]
    fn checksum_loop_body_holding_a_brace_in_a_string_is_removed_whole() {
        let src: &str = "/* Digital.ai */ var d = [1]; for (var __chk = 0; __chk < d.length; __chk++) { d[__chk] ^= 0x42; var s = '}'; } var kept = 1;";
        let opts: ProtectorOptions = ProtectorOptions {
            i_have_authorization: true,
        };
        let out: ProtectorOutput = deobfuscate(src, &opts).unwrap();
        assert!(!out.source.contains("__chk"));
        assert!(out.source.contains("var kept = 1;"));
    }
}
