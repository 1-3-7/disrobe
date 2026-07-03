use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::batch::expand::expand_repeated;

pub const MAX_FOR_ITERATIONS: usize = 4096;

static FOR_L: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r#"(?i)^\s*for\s+/l\s+%%?(?P<var>[A-Za-z])\s+in\s*\(\s*(?P<start>-?\d+)\s*,\s*(?P<step>-?\d+)\s*,\s*(?P<end>-?\d+)\s*\)\s*do\s+(?P<body>.+)$"#,
    )
});

static FOR_F_STRING: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r#"(?i)^\s*for\s+/f\s+(?:"(?P<opts>[^"]*)"\s+)?%%?(?P<var>[A-Za-z])\s+in\s*\(\s*(?P<src>"[^"]*"|[^)]*?)\s*\)\s*do\s+(?P<body>.+)$"#,
    )
});

#[derive(Debug, Clone)]
pub struct ForLoop {
    pub var: char,
    pub iterations: Vec<String>,
    pub body: String,
    pub kind: ForKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForKind {
    Numeric,
    StringTokens,
}

#[must_use]
pub fn parse_for_l(line: &str) -> Option<ForLoop> {
    let cap: regex::Captures<'_> = FOR_L.captures(line)?;
    let var: char = cap.name("var")?.as_str().chars().next()?;
    let start: i64 = cap.name("start")?.as_str().parse::<i64>().ok()?;
    let step: i64 = cap.name("step")?.as_str().parse::<i64>().ok()?;
    let end: i64 = cap.name("end")?.as_str().parse::<i64>().ok()?;
    let body: String = cap.name("body")?.as_str().trim().to_owned();
    let iterations: Vec<String> = numeric_sequence(start, step, end)?;
    Some(ForLoop {
        var,
        iterations,
        body,
        kind: ForKind::Numeric,
    })
}

fn numeric_sequence(start: i64, step: i64, end: i64) -> Option<Vec<String>> {
    if step == 0 {
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    let mut current: i64 = start;
    while (step > 0 && current <= end) || (step < 0 && current >= end) {
        out.push(current.to_string());
        if out.len() > MAX_FOR_ITERATIONS {
            return None;
        }
        current = current.checked_add(step)?;
    }
    Some(out)
}

#[must_use]
pub fn parse_for_f_string(
    line: &str,
    env: &BTreeMap<String, String>,
    args: &[String],
    delayed: bool,
) -> Option<ForLoop> {
    let cap: regex::Captures<'_> = FOR_F_STRING.captures(line)?;
    let var: char = cap.name("var")?.as_str().chars().next()?;
    let body: String = cap.name("body")?.as_str().trim().to_owned();
    let opts: &str = cap
        .name("opts")
        .map_or("", |m: regex::Match<'_>| m.as_str());
    let src_raw: &str = cap.name("src")?.as_str().trim();

    let usebackq: bool = opts.to_ascii_lowercase().contains("usebackq");
    let literal: String = unwrap_for_source(src_raw, usebackq)?;
    let (expanded, _): (String, crate::batch::expand::ExpandStats) =
        expand_repeated(&literal, env, args, delayed, 8);

    let delims: Vec<char> = parse_delims(opts);
    let tokens_spec: TokenSpec = parse_tokens(opts);
    let iterations: Vec<String> = tokenise(&expanded, &delims, tokens_spec);
    Some(ForLoop {
        var,
        iterations,
        body,
        kind: ForKind::StringTokens,
    })
}

fn unwrap_for_source(src: &str, usebackq: bool) -> Option<String> {
    let trimmed: &str = src.trim();
    if usebackq
        && let Some(inner) = trimmed
            .strip_prefix('\'')
            .and_then(|s: &str| s.strip_suffix('\''))
    {
        return Some(inner.to_owned());
    }
    if let Some(inner) = trimmed
        .strip_prefix('"')
        .and_then(|s: &str| s.strip_suffix('"'))
    {
        return Some(inner.to_owned());
    }
    None
}

#[derive(Debug, Clone, Copy)]
enum TokenSpec {
    All,
    Single(usize),
}

fn parse_tokens(opts: &str) -> TokenSpec {
    for part in opts.split_whitespace() {
        let lower: String = part.to_ascii_lowercase();
        if let Some(spec) = lower.strip_prefix("tokens=") {
            if spec == "*" {
                return TokenSpec::All;
            }
            if let Ok(n) = spec.parse::<usize>() {
                return TokenSpec::Single(n);
            }
            if let Some((first, _)) = spec.split_once(',')
                && let Ok(n) = first.parse::<usize>()
            {
                return TokenSpec::Single(n);
            }
        }
    }
    TokenSpec::All
}

fn parse_delims(opts: &str) -> Vec<char> {
    match opts.split("delims=").nth(1) {
        Some(part) => part.chars().take_while(|c: &char| *c != ' ').collect(),
        None => vec![' ', '\t'],
    }
}

fn tokenise(value: &str, delims: &[char], spec: TokenSpec) -> Vec<String> {
    match spec {
        TokenSpec::All => vec![value.to_owned()],
        TokenSpec::Single(n) => {
            if n == 0 {
                return vec![value.to_owned()];
            }
            let tokens: Vec<&str> = value
                .split(|c: char| delims.contains(&c))
                .filter(|t: &&str| !t.is_empty())
                .collect();
            tokens
                .get(n - 1)
                .map_or_else(Vec::new, |t: &&str| vec![(*t).to_owned()])
        }
    }
}

#[must_use]
pub fn unroll(loop_def: &ForLoop) -> Vec<String> {
    let var_pat_percent: String = format!("%%{}", loop_def.var);
    let var_pat_single: String = format!("%{}", loop_def.var);
    loop_def
        .iterations
        .iter()
        .map(|value: &String| {
            loop_def
                .body
                .replace(&var_pat_percent, value)
                .replace(&var_pat_single, value)
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn env_of(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v): &(&str, &str)| (k.to_ascii_uppercase(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn for_l_unrolls_numeric() {
        let def: ForLoop = parse_for_l("for /l %%i in (1,1,3) do echo %%i").expect("parse");
        let lines: Vec<String> = unroll(&def);
        assert_eq!(lines, vec!["echo 1", "echo 2", "echo 3"]);
    }

    #[test]
    fn for_l_descending() {
        let def: ForLoop = parse_for_l("for /l %%i in (3,-1,1) do echo %%i").expect("parse");
        assert_eq!(unroll(&def), vec!["echo 3", "echo 2", "echo 1"]);
    }

    #[test]
    fn for_l_zero_step_is_none() {
        assert!(parse_for_l("for /l %%i in (1,0,3) do echo %%i").is_none());
    }

    #[test]
    fn for_f_tokens_all_passes_value() {
        let env: BTreeMap<String, String> = env_of(&[("V", "hello world")]);
        let def: ForLoop = parse_for_f_string(
            "for /F \"tokens=*\" %%A in (\"!V!\") do echo %%A",
            &env,
            &[],
            true,
        )
        .expect("parse");
        assert_eq!(unroll(&def), vec!["echo hello world"]);
    }

    #[test]
    fn for_f_char_extraction_single_token() {
        let env: BTreeMap<String, String> = env_of(&[("V", "a-b-c")]);
        let def: ForLoop = parse_for_f_string(
            "for /f \"tokens=2 delims=-\" %%A in (\"%V%\") do echo %%A",
            &env,
            &[],
            false,
        )
        .expect("parse");
        assert_eq!(unroll(&def), vec!["echo b"]);
    }

    #[test]
    fn for_f_literal_string() {
        let def: ForLoop = parse_for_f_string(
            "for /f \"tokens=*\" %%A in (\"calc.exe\") do start %%A",
            &env_of(&[]),
            &[],
            false,
        )
        .expect("parse");
        assert_eq!(unroll(&def), vec!["start calc.exe"]);
    }
}
