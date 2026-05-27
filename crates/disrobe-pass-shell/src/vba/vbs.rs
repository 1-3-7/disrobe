use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct VbsReport {
    pub chr_substitutions: usize,
    pub strreverse_unwraps: usize,
    pub execute_unwraps: usize,
    pub output: String,
}

static CHR_CALL: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?i)Chr(?:W|B)?\s*\(\s*(\d{1,5})\s*\)"));

static STRREVERSE: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r#"(?i)StrReverse\s*\(\s*"([^"]*)"\s*\)"#));

static EXECUTE: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(r#"(?i)Execute(?:Global)?\s*\(\s*"([^"]*)"\s*\)"#)
});

static CONCAT: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r#""([^"]*)"\s*&\s*"([^"]*)""#));

#[must_use]
pub fn deobfuscate_vbs(input: &str) -> VbsReport {
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
    current = EXECUTE
        .replace_all(&current, |c: &regex::Captures<'_>| {
            exec_subs += 1;
            c.get(1)
                .map(|m: regex::Match<'_>| m.as_str().to_owned())
                .unwrap_or_default()
        })
        .into_owned();
    VbsReport {
        chr_substitutions: chr_subs,
        strreverse_unwraps: rev_subs,
        execute_unwraps: exec_subs,
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
}
