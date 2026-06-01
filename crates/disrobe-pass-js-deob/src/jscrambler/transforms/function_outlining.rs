use core::ops::Range;
use std::collections::BTreeMap;

use regex::Regex;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::error::{Error, Result};
use crate::jscrambler::scanner::{apply_splice_edits, find_brace_close, find_paren_close, skip_ws};

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    let outlined: BTreeMap<String, OutlinedFn> = collect_outlined_functions(source);
    let mut count: usize = 0;
    for (name, body) in &outlined {
        let Ok(re): core::result::Result<Regex, regex::Error> =
            Regex::new(&format!(r"\b{}\s*\(", regex::escape(name)))
        else {
            continue;
        };
        let callsites: usize = re.find_iter(source).count().saturating_sub(1);
        if callsites == 1 && body.is_short {
            count += 1;
        }
    }
    count
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let outlined: BTreeMap<String, OutlinedFn> = collect_outlined_functions(source);
    if outlined.is_empty() {
        return TransformOutput::noop(source);
    }
    let mut stats: TransformStats = TransformStats::default();
    let mut current: String = source.to_owned();
    for (name, info) in &outlined {
        let Ok(call_re): core::result::Result<Regex, regex::Error> =
            Regex::new(&format!(r"\b{}\s*\(\s*\)", regex::escape(name)))
        else {
            continue;
        };
        let matches: Vec<Range<usize>> = call_re
            .find_iter(&current)
            .map(|m: regex::Match<'_>| m.range())
            .collect();
        let callsite_only: Vec<Range<usize>> = matches
            .into_iter()
            .filter(|r: &Range<usize>| !overlaps(r, &info.decl_range))
            .collect();
        if callsite_only.len() != 1 || !info.is_short {
            continue;
        }
        stats.matched += 1;
        let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
        edits.push((
            callsite_only[0].clone(),
            Some(format!("({})", info.body_expr)),
        ));
        edits.push((info.decl_range.clone(), Some(String::new())));
        let (rewritten, applied): (String, usize) = apply_splice_edits(&current, &mut edits);
        current = rewritten;
        stats.reversed += applied;
    }
    TransformOutput {
        source: current,
        stats,
    }
}

pub(in crate::jscrambler) fn reverse_strict(
    source: &str,
    opts: &TransformOpts,
) -> Result<TransformOutput> {
    let out: TransformOutput = reverse(source, opts);
    if out.stats.matched == 0 && !out.stats.errors.is_empty() {
        return Err(Error::TransformNotYetImplemented {
            transform: "functionOutlining",
        });
    }
    Ok(out)
}

#[derive(Debug, Clone)]
struct OutlinedFn {
    decl_range: Range<usize>,
    body_expr: String,
    is_short: bool,
}

const fn overlaps(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

fn collect_outlined_functions(source: &str) -> BTreeMap<String, OutlinedFn> {
    let mut out: BTreeMap<String, OutlinedFn> = BTreeMap::new();
    let Ok(decl_re): core::result::Result<Regex, regex::Error> =
        Regex::new(r"function\s+([A-Za-z_$][\w$]*)\s*\(\s*\)\s*\{")
    else {
        return out;
    };
    let bytes: &[u8] = source.as_bytes();
    for cap in decl_re.captures_iter(source) {
        let Some(whole) = cap.get(0) else { continue };
        let Some(name) = cap.get(1) else { continue };
        let brace_open: usize = whole.end() - 1;
        let Some(brace_close): Option<usize> = find_brace_close(bytes, brace_open + 1) else {
            continue;
        };
        let after_close: usize = skip_ws(bytes, brace_close + 1);
        let decl_end: usize = if bytes.get(after_close) == Some(&b';') {
            after_close + 1
        } else {
            brace_close + 1
        };
        let body: &str = match source.get(brace_open + 1..brace_close) {
            Some(s) => s.trim(),
            None => continue,
        };
        let expr: Option<String> = single_return_expr(body);
        if let Some(e) = expr {
            let is_short: bool = e.len() <= 120 && !e.contains('\n');
            out.insert(
                name.as_str().to_owned(),
                OutlinedFn {
                    decl_range: whole.start()..decl_end,
                    body_expr: e,
                    is_short,
                },
            );
        }
    }
    let Ok(arrow_re): core::result::Result<Regex, regex::Error> =
        Regex::new(r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*function\s*\(\s*\)\s*\{")
    else {
        return out;
    };
    for cap in arrow_re.captures_iter(source) {
        let Some(whole) = cap.get(0) else { continue };
        let Some(name) = cap.get(1) else { continue };
        let brace_open: usize = whole.end() - 1;
        let Some(brace_close): Option<usize> = find_brace_close(bytes, brace_open + 1) else {
            continue;
        };
        let after_close: usize = skip_ws(bytes, brace_close + 1);
        let decl_end: usize = if bytes.get(after_close) == Some(&b';') {
            after_close + 1
        } else {
            brace_close + 1
        };
        let body: &str = match source.get(brace_open + 1..brace_close) {
            Some(s) => s.trim(),
            None => continue,
        };
        let expr: Option<String> = single_return_expr(body);
        if let Some(e) = expr {
            let is_short: bool = e.len() <= 120 && !e.contains('\n');
            out.insert(
                name.as_str().to_owned(),
                OutlinedFn {
                    decl_range: whole.start()..decl_end,
                    body_expr: e,
                    is_short,
                },
            );
        }
    }
    out
}

fn single_return_expr(body: &str) -> Option<String> {
    let trimmed: &str = body.trim();
    let stripped: &str = trimmed.strip_prefix("return")?;
    let after_kw: &str = stripped.trim_start();
    let final_expr: &str = after_kw.strip_suffix(';').unwrap_or(after_kw).trim();
    if final_expr.is_empty() {
        return None;
    }
    let bytes: &[u8] = final_expr.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if matches!(b, b'(' | b'[' | b'{') {
            let end: usize = match b {
                b'(' => find_paren_close(bytes, i + 1)?,
                _ => find_brace_close(bytes, i + 1)?,
            };
            i = end + 1;
            continue;
        }
        if matches!(b, b';') {
            return None;
        }
        i += 1;
    }
    Some(final_expr.to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detect_finds_single_callsite_outlined_function() {
        let src: &str = "function _outlined1(){return 42;} var x = _outlined1();";
        assert!(detect(src) >= 1);
    }

    #[test]
    fn inlines_single_callsite_outlined_function() {
        let src: &str = "function _o1(){return 42;} var x = _o1();";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.stats.reversed >= 1);
        assert!(out.source.contains("(42)"));
        assert!(!out.source.contains("_o1()"));
    }

    #[test]
    fn skips_multi_callsite_function() {
        let src: &str = "function _o2(){return 1;} var a = _o2(); var b = _o2();";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 0);
    }

    #[test]
    fn handles_var_function_form() {
        let src: &str = "var _o3 = function(){return globalThis;}; var g = _o3();";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.stats.reversed >= 1);
        assert!(out.source.contains("(globalThis)"));
    }

    #[test]
    fn skips_long_body() {
        let long_expr: String = "a".repeat(200);
        let src: String = format!("function _o4(){{return {long_expr};}} var x = _o4();");
        let out: TransformOutput = reverse(&src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 0);
    }

    #[test]
    fn returns_typed_error_in_strict_mode_on_compile_failure() {
        let src: &str = "var x = 1;";
        let res: Result<TransformOutput> = reverse_strict(src, &TransformOpts::default());
        assert!(res.is_ok());
    }

    #[test]
    fn reverse_is_noop_when_nothing_matches() {
        let src: &str = "var x = 1;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
        assert_eq!(out.stats.matched, 0);
    }
}
