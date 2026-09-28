use lazy_regex::regex;
use regex::Regex;
use serde::Serialize;
use std::ops::Range;
use std::sync::LazyLock;

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

static CHR_CALL: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"(?i)\bChr(?:W|B)?\s*\(\s*(\d{1,5})\s*\)"));

static STRREVERSE: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r#"(?i)\bStrReverse\s*\(\s*"((?:[^"]|"")*)"\s*\)"#));

static EXECUTE: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r#"(?is)(^|[^.\w])(Execute(?:Global)?\s*\(\s*"((?:[^"]|"")*)"\s*\))"#));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lexeme {
    Literal,
    Unterminated,
    Comment,
}

fn lexemes(text: &str) -> Vec<(Range<usize>, Lexeme)> {
    let bytes: &[u8] = text.as_bytes();
    let mut spans: Vec<(Range<usize>, Lexeme)> = Vec::new();
    let mut index: usize = 0;
    while let Some(byte) = bytes.get(index) {
        let start: usize = index;
        match byte {
            b'"' => {
                index += 1;
                let kind: Lexeme = loop {
                    match (bytes.get(index), bytes.get(index + 1)) {
                        (None | Some(b'\n'), _) => break Lexeme::Unterminated,
                        (Some(b'"'), Some(b'"')) => index += 2,
                        (Some(b'"'), _) => {
                            index += 1;
                            break Lexeme::Literal;
                        }
                        (Some(_), _) => index += 1,
                    }
                };
                spans.push((start..index, kind));
            }
            b'\'' => {
                while bytes.get(index).is_some_and(|b: &u8| *b != b'\n') {
                    index += 1;
                }
                spans.push((start..index, Lexeme::Comment));
            }
            _ => index += 1,
        }
    }
    spans
}

fn in_code(spans: &[(Range<usize>, Lexeme)], position: usize) -> bool {
    let after: usize =
        spans.partition_point(|(range, _): &(Range<usize>, Lexeme)| range.end <= position);
    spans
        .get(after)
        .is_none_or(|(range, _): &(Range<usize>, Lexeme)| range.start > position)
}

fn binds_tighter_than_concatenation(neighbour: Option<char>) -> bool {
    matches!(neighbour, Some('+' | '-' | '*' | '/' | '\\' | '^'))
}

fn fold_literal_concatenation(text: &str) -> String {
    let spans: Vec<(Range<usize>, Lexeme)> = lexemes(text);
    let mut out: String = String::with_capacity(text.len());
    let mut cursor: usize = 0;
    let mut index: usize = 0;
    while let Some((first, kind)) = spans.get(index) {
        index += 1;
        if *kind != Lexeme::Literal
            || binds_tighter_than_concatenation(text[..first.start].trim_end().chars().last())
        {
            continue;
        }
        let mut end: usize = first.end;
        let mut inner: String = text[first.start + 1..first.end - 1].to_owned();
        while let Some((next, Lexeme::Literal)) = spans.get(index) {
            let gap: &str = &text[end..next.start];
            let following: Option<char> = text[next.end..]
                .trim_start_matches([' ', '\t'])
                .chars()
                .next();
            if gap.contains('\n')
                || gap.trim() != "&"
                || binds_tighter_than_concatenation(following)
            {
                break;
            }
            inner.push_str(&text[next.start + 1..next.end - 1]);
            end = next.end;
            index += 1;
        }
        if end != first.end {
            out.push_str(&text[cursor..first.start]);
            out.push('"');
            out.push_str(&inner);
            out.push('"');
            cursor = end;
        }
    }
    out.push_str(&text[cursor..]);
    out
}

#[must_use]
pub fn deobfuscate_vbs(input: &str) -> VbsReport {
    deobfuscate_vbs_with_policy(input, DynamicPolicy::default())
}

#[must_use]
pub fn deobfuscate_vbs_with_policy(input: &str, policy: DynamicPolicy) -> VbsReport {
    let mut chr_subs: usize = 0;
    let spans: Vec<(Range<usize>, Lexeme)> = lexemes(input);
    let mut current: String = CHR_CALL
        .replace_all(input, |c: &regex::Captures<'_>| {
            let whole: Option<regex::Match<'_>> = c.get(0);
            if !whole.is_some_and(|m: regex::Match<'_>| in_code(&spans, m.start())) {
                return whole.map_or_else(String::new, |m: regex::Match<'_>| m.as_str().to_owned());
            }
            chr_subs += 1;
            let n: u32 = c
                .get(1)
                .and_then(|m: regex::Match<'_>| m.as_str().parse::<u32>().ok())
                .unwrap_or(0);
            char::from_u32(n).map_or_else(String::new, |ch: char| vbs_literal(&ch.to_string()))
        })
        .into_owned();
    current = fold_literal_concatenation(&current);
    let mut rev_subs: usize = 0;
    let spans: Vec<(Range<usize>, Lexeme)> = lexemes(&current);
    current = STRREVERSE
        .replace_all(&current, |c: &regex::Captures<'_>| {
            let whole: Option<regex::Match<'_>> = c.get(0);
            if !whole.is_some_and(|m: regex::Match<'_>| in_code(&spans, m.start())) {
                return whole.map_or_else(String::new, |m: regex::Match<'_>| m.as_str().to_owned());
            }
            rev_subs += 1;
            let body: &str = c.get(1).map_or("", |m: regex::Match<'_>| m.as_str());
            vbs_literal(&body.replace("\"\"", "\"").chars().rev().collect::<String>())
        })
        .into_owned();
    let mut exec_subs: usize = 0;
    let mut eval_depth: usize = 0;
    let mut walls: Vec<String> = Vec::new();
    loop {
        let spans: Vec<(Range<usize>, Lexeme)> = lexemes(&current);
        let Some((call, body)): Option<(Range<usize>, String)> = EXECUTE
            .captures_iter(&current)
            .find_map(|c: regex::Captures<'_>| {
                let call: regex::Match<'_> = c.get(2)?;
                let body: regex::Match<'_> = c.get(3)?;
                in_code(&spans, call.start())
                    .then(|| (call.range(), body.as_str().replace("\"\"", "\"")))
            })
        else {
            break;
        };
        let next_depth: usize = eval_depth + 1;
        if !policy.permits_depth(next_depth) {
            walls.push(format!(
                "Execute depth {next_depth} exceeds static cap {}; re-run with --allow-dynamic to unwrap further",
                policy.max_eval_depth()
            ));
            break;
        }
        exec_subs += 1;
        current.replace_range(call, &body);
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

fn vbs_literal(text: &str) -> String {
    format!("\"{}\"", text.replace('"', "\"\""))
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
    fn folded_quote_characters_stay_escaped_vbs_literals() {
        let r: VbsReport = deobfuscate_vbs(r#"x = "say " & Chr(34) & "hi" & Chr(34)"#);
        assert_eq!(r.output, r#"x = "say ""hi""""#);
        let r: VbsReport = deobfuscate_vbs(r#"y = StrReverse("""ih"" yas")"#);
        assert_eq!(r.output, r#"y = "say ""hi""""#);
    }

    #[test]
    fn unwraps_strreverse() {
        let r: VbsReport = deobfuscate_vbs(r#"Execute(StrReverse("xobgsM"))"#);
        assert!(r.strreverse_unwraps >= 1);
        assert!(r.output.contains("Msgbox"));
    }

    #[test]
    fn method_calls_and_longer_names_are_not_unwrapped() {
        let src: &str =
            "Set m = re.Execute(\"Hello World 2026\")\nx = MyChr(65) & AStrReverse(\"ba\")";
        let r: VbsReport = deobfuscate_vbs(src);
        assert_eq!(r.output, src);
        assert_eq!(
            (r.chr_substitutions, r.strreverse_unwraps, r.execute_unwraps),
            (0, 0, 0)
        );
        let r: VbsReport = deobfuscate_vbs("If ok Then Execute(\"MsgBox 1\")");
        assert_eq!(r.output, "If ok Then MsgBox 1");
    }

    #[test]
    fn string_literals_and_comments_are_not_rewritten() {
        let src: &str = "If Left$(t, 1) = \"&\" Then\n    t = Mid$(t, 3) ' Chr(65) & \"x\"\nEnd If\nMsgBox \"Use Chr(65) or StrReverse(\"\"ba\"\")\"\ny = \"a\" & \"b\" + 1\nz = 1 + \"a\" & \"b\"";
        let r: VbsReport = deobfuscate_vbs(src);
        assert_eq!(r.output, src);
        assert_eq!((r.chr_substitutions, r.strreverse_unwraps), (0, 0));
        let r: VbsReport = deobfuscate_vbs("s = \"a\" & \"b\" & Chr(99) ' tail \"\n");
        assert_eq!(r.output, "s = \"abc\" ' tail \"\n");
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
