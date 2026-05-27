use std::ops::Range;

use regex::Regex;
use serde::Serialize;

use super::scanner::{apply_splice_edits, find_paren_close, scan_balanced_brace, skip_whitespace};

#[derive(Debug, Clone, Serialize)]
pub struct LockReversalResult {
    pub guards_stripped: usize,
    pub rewritten_source: String,
}

#[must_use]
pub fn strip_locks(source: &str) -> LockReversalResult {
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"\bif\s*\(") else {
        return passthrough(source);
    };
    let bytes: &[u8] = source.as_bytes();
    for mat in re.find_iter(source) {
        let open: usize = mat.end() - 1;
        let Some(close): Option<usize> = find_paren_close(bytes, open + 1) else {
            continue;
        };
        let cond: &str = source[open + 1..close].trim();
        if !looks_like_lock_check(cond) {
            continue;
        }
        let body_start: usize = skip_whitespace(bytes, close + 1);
        if body_start >= bytes.len() || bytes[body_start] != b'{' {
            continue;
        }
        let Some(body_close): Option<usize> = scan_balanced_brace(source, body_start + 1) else {
            continue;
        };
        let body: &str = source[body_start + 1..body_close].trim();
        if !body_is_pure_termination(body) {
            continue;
        }
        edits.push((mat.start()..body_close + 1, Some(String::new())));
    }
    if edits.is_empty() {
        return passthrough(source);
    }
    let (rewritten, stripped): (String, usize) = apply_splice_edits(source, &mut edits);
    LockReversalResult {
        guards_stripped: stripped,
        rewritten_source: rewritten,
    }
}

fn passthrough(source: &str) -> LockReversalResult {
    LockReversalResult {
        guards_stripped: 0,
        rewritten_source: source.to_owned(),
    }
}

fn looks_like_lock_check(cond: &str) -> bool {
    let lower: String = cond.to_ascii_lowercase();
    let hits_environment: bool = lower.contains("window.location.hostname")
        || lower.contains("location.hostname")
        || lower.contains("document.domain")
        || lower.contains("navigator.useragent")
        || lower.contains("location.href")
        || lower.contains("window.top")
        || lower.contains("self !== top")
        || lower.contains("self!==top")
        || lower.contains("self !== window.top")
        || lower.contains("date.now()")
        || lower.contains("new date(")
        || lower.contains("debugger");
    let hits_operator: bool = cond.contains("!==")
        || cond.contains("!=")
        || cond.contains("===")
        || cond.contains("==")
        || cond.contains('<')
        || cond.contains('>');
    hits_environment && hits_operator
}

fn body_is_pure_termination(body: &str) -> bool {
    let normalized: String = body.split_whitespace().collect::<Vec<&str>>().join(" ");
    matches!(
        normalized.as_str(),
        "return;" | "return" | "return void 0;" | "return undefined;"
    ) || normalized.starts_with("throw ")
        || normalized.starts_with("window.location")
        || normalized.starts_with("document.location")
        || normalized.starts_with("location.href")
        || normalized.starts_with("while (true)")
        || normalized.starts_with("for(;;)")
        || normalized.starts_with("for (;;)")
        || normalized.starts_with("debugger")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_hostname_guard_with_return() {
        let src: &str = "function boot(){\n  if (window.location.hostname !== 'attacker.com') { return; }\n  doStuff();\n}";
        let r: LockReversalResult = strip_locks(src);
        assert_eq!(r.guards_stripped, 1);
        assert!(!r.rewritten_source.contains("attacker.com"));
        assert!(r.rewritten_source.contains("doStuff()"));
    }

    #[test]
    fn strips_debugger_anti_devtools_guard() {
        let src: &str = "if (new Date().getTime() - t > 100) { debugger; while (true) {} }\nrun();";
        let r: LockReversalResult = strip_locks(src);
        assert!(r.guards_stripped >= 1);
        assert!(r.rewritten_source.contains("run()"));
    }

    #[test]
    fn leaves_unrelated_branches_intact() {
        let src: &str = "if (count > 10) { console.log('over'); }";
        let r: LockReversalResult = strip_locks(src);
        assert_eq!(r.guards_stripped, 0);
        assert_eq!(r.rewritten_source, src);
    }
}
