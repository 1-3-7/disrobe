use std::ops::Range;

use regex::Regex;
use serde::Serialize;

use super::scanner::{apply_splice_edits, find_paren_close, scan_balanced_brace, skip_whitespace};

#[derive(Debug, Clone, Serialize)]
pub struct IntegrityReversalResult {
    pub loops_stripped: usize,
    pub rewritten_source: String,
}

#[must_use]
pub fn strip_integrity(source: &str) -> IntegrityReversalResult {
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    collect_setinterval_integrity(source, &mut edits);
    collect_self_check_function(source, &mut edits);
    if edits.is_empty() {
        return IntegrityReversalResult {
            loops_stripped: 0,
            rewritten_source: source.to_owned(),
        };
    }
    let (rewritten, stripped): (String, usize) = apply_splice_edits(source, &mut edits);
    IntegrityReversalResult {
        loops_stripped: stripped,
        rewritten_source: rewritten,
    }
}

fn collect_setinterval_integrity(source: &str, edits: &mut Vec<(Range<usize>, Option<String>)>) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"(?:setInterval|setTimeout)\s*\(\s*function\s*\(\s*\)\s*\{")
    else {
        return;
    };
    let bytes: &[u8] = source.as_bytes();
    for mat in re.find_iter(source) {
        let body_open: usize = mat.end() - 1;
        let Some(body_close): Option<usize> = scan_balanced_brace(source, body_open + 1) else {
            continue;
        };
        let body: &str = &source[body_open + 1..body_close];
        if !body_is_integrity_check(body) {
            continue;
        }
        let after_body: usize = skip_whitespace(bytes, body_close + 1);
        if after_body >= bytes.len() || bytes[after_body] != b',' {
            continue;
        }
        let Some(call_close): Option<usize> = find_call_close(bytes, mat.start()) else {
            continue;
        };
        let mut tail: usize = call_close + 1;
        if bytes.get(tail) == Some(&b';') {
            tail += 1;
        }
        edits.push((mat.start()..tail, Some(String::new())));
    }
}

fn collect_self_check_function(source: &str, edits: &mut Vec<(Range<usize>, Option<String>)>) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r"(?ms)function\s+[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{[^{}]{0,1024}\.toString\s*\(\s*\)\s*\.\s*replace[^{}]*?\}",
    ) else {
        return;
    };
    for mat in re.find_iter(source) {
        let snippet: &str = mat.as_str();
        if !snippet.contains("RegExp")
            && !snippet.contains("hash")
            && !snippet.contains("integrity")
        {
            continue;
        }
        edits.push((mat.start()..mat.end(), Some(String::new())));
    }
}

fn body_is_integrity_check(body: &str) -> bool {
    let has_self_ref: bool =
        body.contains(".toString") || body.contains("constructor") || body.contains("callee");
    let has_compare: bool = body.contains("hash")
        || body.contains("===")
        || body.contains("!==")
        || body.contains("RegExp")
        || body.contains("integrity");
    let has_action: bool = body.contains("location")
        || body.contains("debugger")
        || body.contains("throw")
        || body.contains("while");
    has_self_ref && has_compare && has_action
}

fn find_call_close(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i: usize = start;
    while i < bytes.len() && bytes[i] != b'(' {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    find_paren_close(bytes, i + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_setinterval_integrity_check() {
        let src: &str = "var n = 1;\nsetInterval(function () { if (boot.toString().replace(/\\s/g, '').length !== 1234) { window.location = 'about:blank'; } }, 1000);\nrun();";
        let r: IntegrityReversalResult = strip_integrity(src);
        assert_eq!(r.loops_stripped, 1);
        assert!(!r.rewritten_source.contains("setInterval"));
        assert!(r.rewritten_source.contains("run()"));
    }

    #[test]
    fn strips_self_check_function_decl() {
        let src: &str = "function checkIntegrity(fn){ var hash = fn.toString().replace(/\\s/g, '').length; if (hash !== 999) throw new Error('integrity'); }\nuseit();";
        let r: IntegrityReversalResult = strip_integrity(src);
        assert!(r.loops_stripped >= 1);
        assert!(r.rewritten_source.contains("useit()"));
    }

    #[test]
    fn leaves_normal_setinterval_alone() {
        let src: &str = "setInterval(function () { tick++; }, 1000);";
        let r: IntegrityReversalResult = strip_integrity(src);
        assert_eq!(r.loops_stripped, 0);
        assert_eq!(r.rewritten_source, src);
    }
}
