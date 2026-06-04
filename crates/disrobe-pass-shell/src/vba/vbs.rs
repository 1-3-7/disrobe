use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

use crate::policy::DynamicPolicy;

#[derive(Debug, Clone, Serialize)]
pub struct VbsReport {
    pub chr_substitutions: usize,
    pub strreverse_unwraps: usize,
    pub execute_unwraps: usize,
    pub eval_depth: usize,
    pub walls: Vec<String>,
    pub output: String,
}

static CHR_CALL: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?i)Chr(?:W|B)?\s*\(\s*(\d{1,5})\s*\)"));

static STRREVERSE: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r#"(?i)StrReverse\s*\(\s*"([^"]*)"\s*\)"#));

static EXECUTE: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(r#"(?is)Execute(?:Global)?\s*\(\s*"((?:[^"]|"")*)"\s*\)"#)
});

static CONCAT: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r#""([^"]*)"\s*&\s*"([^"]*)""#));

/// Statically deobfuscate a `VBScript` snippet (`Chr()` folding, concatenation, `StrReverse`,
/// and `Execute`/`ExecuteGlobal` unwrapping) under the default static-only policy.
#[must_use]
pub fn deobfuscate_vbs(input: &str) -> VbsReport {
    deobfuscate_vbs_with_policy(input, DynamicPolicy::default())
}

/// Deobfuscate `VBScript`, unwrapping nested `Execute`/`ExecuteGlobal` layers up to the
/// [`DynamicPolicy`] eval-depth cap.
///
/// Each `Execute(...)` peel that re-exposes a further `Execute` increments eval depth; once
/// the static cap is reached the remaining dynamic layer is left intact and a wall is recorded,
/// so a self-rebuilding dropper is never unwound past the safe horizon without `--allow-dynamic`.
#[must_use]
pub fn deobfuscate_vbs_with_policy(input: &str, policy: DynamicPolicy) -> VbsReport {
    let mut current: String = input.to_owned();
    let mut chr_subs: usize = 0;
    current = CHR_CALL
        .replace_all(&current, |c: &regex::Captures<'_>| {
            chr_subs += 1;
            let n: u32 = c
                .get(1)
                .and_then(|m: regex::Match<'_>| m.as_str().parse::<u32>().ok())
                .unwrap_or(0);
            char::from_u32(n).map_or_else(|| String::new(), |ch: char| format!("\"{ch}\""))
        })
        .into_owned();
    for _ in 0..16usize {
        let next: std::borrow::Cow<'_, str> = CONCAT.replace_all(&current, "\"$1$2\"");
        if next == current {
            break;
        }
        current = next.into_owned();
    }
    let mut rev_subs: usize = 0;
    current = STRREVERSE
        .replace_all(&current, |c: &regex::Captures<'_>| {
            rev_subs += 1;
            let s: &str = c.get(1).map(|m: regex::Match<'_>| m.as_str()).unwrap_or("");
            format!("\"{}\"", s.chars().rev().collect::<String>())
        })
        .into_owned();
    let mut exec_subs: usize = 0;
    let mut eval_depth: usize = 0;
    let mut walls: Vec<String> = Vec::new();
    while EXECUTE.is_match(&current) {
        let next_depth: usize = eval_depth + 1;
        if !policy.permits_depth(next_depth) {
            walls.push(format!(
                "Execute depth {next_depth} exceeds static cap {}; re-run with --allow-dynamic to unwrap further",
                policy.max_eval_depth()
            ));
            break;
        }
        let unwrapped: String = EXECUTE
            .replace(&current, |c: &regex::Captures<'_>| {
                exec_subs += 1;
                c.get(1)
                    .map(|m: regex::Match<'_>| m.as_str().replace("\"\"", "\""))
                    .unwrap_or_default()
            })
            .into_owned();
        if unwrapped == current {
            break;
        }
        current = unwrapped;
        eval_depth = next_depth;
    }
    VbsReport {
        chr_substitutions: chr_subs,
        strreverse_unwraps: rev_subs,
        execute_unwraps: exec_subs,
        eval_depth,
        walls,
        output: current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_chr_concatenations() {
        let src: &str = "MsgBox Chr(72) & Chr(105)";
        let r: VbsReport = deobfuscate_vbs(src);
        assert!(r.chr_substitutions >= 2);
        assert!(r.output.contains("\"Hi\""));
    }

    #[test]
    fn unwraps_strreverse() {
        let r: VbsReport = deobfuscate_vbs(r#"Execute(StrReverse("xobgsM"))"#);
        assert!(r.strreverse_unwraps >= 1);
        assert!(r.output.contains("Msgbox"));
    }

    fn nested_execute(depth: usize) -> String {
        let mut inner: String = "WScript.Echo 1".to_owned();
        for _ in 0..depth {
            let escaped: String = inner.replace('"', "\"\"");
            inner = format!("Execute(\"{escaped}\")");
        }
        inner
    }

    #[test]
    fn static_policy_caps_nested_execute_depth() {
        let src: String = nested_execute(4);
        let r: VbsReport = deobfuscate_vbs(&src);
        assert_eq!(r.eval_depth, 2, "eval_depth={}", r.eval_depth);
        assert!(
            !r.walls.is_empty(),
            "nested Execute must surface a static-cap wall; out={}",
            r.output
        );
        assert!(
            r.output.contains("Execute"),
            "layers should remain under static cap; out={}",
            r.output
        );
    }

    #[test]
    fn allow_dynamic_unwraps_deeper_execute() {
        let src: String = nested_execute(4);
        let r: VbsReport = deobfuscate_vbs_with_policy(&src, DynamicPolicy::AllowDynamic);
        assert_eq!(r.eval_depth, 4, "eval_depth={}", r.eval_depth);
        assert!(r.output.contains("WScript.Echo 1"), "out={}", r.output);
        assert!(r.walls.is_empty());
    }
}
