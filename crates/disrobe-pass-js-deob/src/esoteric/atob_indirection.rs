use std::borrow::Cow;

use base64::Engine as _;
use regex::{Captures, Regex};
use serde::Serialize;

const MAX_RECURSIVE_DEPTH: usize = 6;

#[derive(Debug, Clone, Default, Serialize)]
pub struct AtobIndirectionStats {
    pub atob_calls_folded: usize,
    pub btoa_calls_folded: usize,
    pub recursive_descents: usize,
    pub failed_decodes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AtobIndirectionResult {
    pub stats: AtobIndirectionStats,
    pub rewritten: String,
    pub recovered_payloads: Vec<String>,
}

#[must_use]
pub fn peel_atob_indirection(source: &str) -> AtobIndirectionResult {
    let mut stats: AtobIndirectionStats = AtobIndirectionStats::default();
    let mut payloads: Vec<String> = Vec::new();
    let after_alias: String = resolve_atob_aliases(source);
    let after_atob: String = fold_atob(&after_alias, &mut stats, &mut payloads);
    let after_btoa: String = fold_btoa(&after_atob, &mut stats);
    let recovered: String = recursive_descend(&after_btoa, &mut stats, &mut payloads, 0);
    AtobIndirectionResult {
        stats,
        rewritten: recovered,
        recovered_payloads: payloads,
    }
}

fn resolve_atob_aliases(source: &str) -> String {
    let after_global: String = strip_global_atob_btoa(source);
    rename_atob_btoa_aliases(&after_global)
}

fn strip_global_atob_btoa(source: &str) -> String {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"\b(?:window|globalThis|self|global)\s*\.\s*(atob|btoa)\b")
    else {
        return source.to_owned();
    };
    re.replace_all(source, |caps: &Captures<'_>| caps[1].to_owned())
        .into_owned()
}

fn rename_atob_btoa_aliases(source: &str) -> String {
    let mut current: String = source.to_owned();
    for target in ["atob", "btoa"] {
        for alias in collect_aliases(&current, target) {
            current = substitute_identifier(&current, &alias, target);
        }
    }
    current
}

fn collect_aliases(source: &str, target: &str) -> Vec<String> {
    let pattern: String = format!(r"(?m)(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*{target}\s*;");
    let Ok(re): Result<Regex, regex::Error> = Regex::new(&pattern) else {
        return Vec::new();
    };
    let mut seen: Vec<String> = Vec::new();
    let mut rejected: Vec<String> = Vec::new();
    for caps in re.captures_iter(source) {
        if let Some(name) = caps.get(1) {
            let alias: String = name.as_str().to_owned();
            if alias == target {
                continue;
            }
            if seen.contains(&alias) {
                rejected.push(alias);
            } else {
                seen.push(alias);
            }
        }
    }
    seen.retain(|a: &String| !rejected.contains(a) && single_assignment(source, a));
    seen
}

fn single_assignment(source: &str, alias: &str) -> bool {
    let pattern: String = format!(r"\b{0}\b\s*=", regex::escape(alias));
    Regex::new(&pattern).is_ok_and(|re: Regex| re.find_iter(source).count() == 1)
}

fn substitute_identifier(source: &str, alias: &str, target: &str) -> String {
    let decl_pattern: String = format!(
        r"(?m)(?:var|let|const)\s+{0}\s*=\s*{target}\s*;\s*",
        regex::escape(alias),
    );
    let stripped: String = Regex::new(&decl_pattern).map_or_else(
        |_| source.to_owned(),
        |decl_re: Regex| decl_re.replace_all(source, "").into_owned(),
    );
    let use_pattern: String = format!(r"\b{0}\b", regex::escape(alias));
    Regex::new(&use_pattern).map_or_else(
        |_| stripped.clone(),
        |use_re: Regex| use_re.replace_all(&stripped, target).into_owned(),
    )
}

fn fold_atob(source: &str, stats: &mut AtobIndirectionStats, payloads: &mut Vec<String>) -> String {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r#"\batob\s*\(\s*(?:'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)")\s*\)"#)
    else {
        return source.to_owned();
    };
    let replaced: Cow<'_, str> = re.replace_all(source, |caps: &Captures<'_>| {
        let raw: Option<&str> = caps.get(1).or_else(|| caps.get(2)).map(|m| m.as_str());
        let Some(payload): Option<&str> = raw else {
            return caps[0].to_owned();
        };
        let unescaped: String = unescape_js_literal(payload);
        decode_base64(&unescaped).map_or_else(
            || {
                stats.failed_decodes += 1;
                caps[0].to_owned()
            },
            |decoded: String| {
                stats.atob_calls_folded += 1;
                payloads.push(decoded.clone());
                js_quote(&decoded)
            },
        )
    });
    replaced.into_owned()
}

fn fold_btoa(source: &str, stats: &mut AtobIndirectionStats) -> String {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r#"\bbtoa\s*\(\s*(?:'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)")\s*\)"#)
    else {
        return source.to_owned();
    };
    let replaced: Cow<'_, str> = re.replace_all(source, |caps: &Captures<'_>| {
        let raw: Option<&str> = caps.get(1).or_else(|| caps.get(2)).map(|m| m.as_str());
        let Some(payload): Option<&str> = raw else {
            return caps[0].to_owned();
        };
        let unescaped: String = unescape_js_literal(payload);
        let encoded: String =
            base64::engine::general_purpose::STANDARD.encode(unescaped.as_bytes());
        stats.btoa_calls_folded += 1;
        js_quote(&encoded)
    });
    replaced.into_owned()
}

fn recursive_descend(
    source: &str,
    stats: &mut AtobIndirectionStats,
    payloads: &mut Vec<String>,
    depth: usize,
) -> String {
    if depth >= MAX_RECURSIVE_DEPTH || !source.contains("atob(") {
        return source.to_owned();
    }
    let folded: String = fold_atob(source, stats, payloads);
    if folded == source {
        return folded;
    }
    stats.recursive_descents += 1;
    recursive_descend(&folded, stats, payloads, depth + 1)
}

fn decode_base64(input: &str) -> Option<String> {
    let trimmed: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes: Vec<u8> = base64::engine::general_purpose::STANDARD
        .decode(trimmed.as_bytes())
        .ok()?;
    let mut out: String = String::with_capacity(bytes.len());
    for b in bytes {
        out.push(b as char);
    }
    Some(out)
}

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

fn js_quote(input: &str) -> String {
    let mut out: String = String::with_capacity(input.len() + 2);
    out.push('"');
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                push_format(&mut out, format_args!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn unescape_js_literal(input: &str) -> String {
    let mut out: String = String::with_capacity(input.len());
    let mut iter: std::str::Chars<'_> = input.chars();
    while let Some(ch) = iter.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match iter.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\'') => out.push('\''),
            Some('"') => out.push('"'),
            Some('0') => out.push('\0'),
            Some('/') => out.push('/'),
            Some('\\') | None => out.push('\\'),
            Some(other) => out.push(other),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn folds_atob_literal() {
        let src: &str = r#"var x = atob("SGVsbG8=");"#;
        let res: AtobIndirectionResult = peel_atob_indirection(src);
        assert_eq!(res.stats.atob_calls_folded, 1);
        assert!(res.rewritten.contains("\"Hello\""));
        assert_eq!(res.recovered_payloads, vec!["Hello".to_owned()]);
    }

    #[test]
    fn folds_btoa_literal() {
        let src: &str = r#"var x = btoa("Hello");"#;
        let res: AtobIndirectionResult = peel_atob_indirection(src);
        assert_eq!(res.stats.btoa_calls_folded, 1);
        assert!(res.rewritten.contains("\"SGVsbG8=\""));
    }

    #[test]
    fn recursive_descent_on_nested() {
        let src: &str = r#"var x = atob("YXRvYigiSGVsbG8iKQ==");"#;
        let res: AtobIndirectionResult = peel_atob_indirection(src);
        assert!(res.stats.atob_calls_folded >= 1);
        assert!(res.recovered_payloads.iter().any(|p| p.contains("Hello")));
    }

    #[test]
    fn leaves_non_constant_atob_alone() {
        let src: &str = "var x = atob(input);";
        let res: AtobIndirectionResult = peel_atob_indirection(src);
        assert_eq!(res.stats.atob_calls_folded, 0);
    }

    #[test]
    fn invalid_base64_does_not_replace_and_marks_failed() {
        let src: &str = r#"var x = atob("!!!notbase64");"#;
        let res: AtobIndirectionResult = peel_atob_indirection(src);
        assert!(res.stats.failed_decodes >= 1);
        assert_eq!(res.stats.atob_calls_folded, 0);
    }

    #[test]
    fn folds_window_atob() {
        let src: &str = r#"var x = window.atob("SGVsbG8=");"#;
        let res: AtobIndirectionResult = peel_atob_indirection(src);
        assert_eq!(res.stats.atob_calls_folded, 1);
        assert!(res.rewritten.contains("\"Hello\""), "got {}", res.rewritten);
    }

    #[test]
    fn folds_globalthis_btoa() {
        let src: &str = r#"var x = globalThis.btoa("Hello");"#;
        let res: AtobIndirectionResult = peel_atob_indirection(src);
        assert_eq!(res.stats.btoa_calls_folded, 1);
        assert!(
            res.rewritten.contains("\"SGVsbG8=\""),
            "got {}",
            res.rewritten
        );
    }

    #[test]
    fn folds_resolved_alias() {
        let src: &str = r#"var _d = atob; var x = _d("SGVsbG8=");"#;
        let res: AtobIndirectionResult = peel_atob_indirection(src);
        assert_eq!(res.stats.atob_calls_folded, 1);
        assert!(res.rewritten.contains("\"Hello\""), "got {}", res.rewritten);
        assert!(
            !res.rewritten.contains("_d"),
            "alias decl/use must be gone: {}",
            res.rewritten
        );
    }

    #[test]
    fn skips_reassigned_alias() {
        let src: &str = r#"var _d = atob; _d = other; var x = _d("SGVsbG8=");"#;
        let res: AtobIndirectionResult = peel_atob_indirection(src);
        assert_eq!(
            res.stats.atob_calls_folded, 0,
            "reassigned alias must not be folded: {}",
            res.rewritten
        );
    }
}
