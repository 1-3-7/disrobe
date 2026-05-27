use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

use super::invoke_obfuscation::{
    InvokeObfuscationLevel, ReverseReport, reverse_string, reverse_token,
};

#[derive(Debug, Clone, Serialize)]
pub struct InvokeStealthReport {
    pub steps: Vec<ReverseReport>,
    pub output: String,
}

static REVERSE_TECH: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(r#"\[\s*[Aa]rray\s*\]::Reverse\s*\(\s*\$([A-Za-z0-9_]+)\s*\)"#)
});

static ROT13: LazyLock<Regex> = LazyLock::new(|| crate::regex_util::safe_regex(r"(?i)ROT13"));

#[must_use]
pub fn reverse_invoke_stealth(input: &str) -> InvokeStealthReport {
    let mut steps: Vec<ReverseReport> = Vec::new();
    let mut current: String = input.to_owned();
    if ROT13.is_match(&current) {
        current = apply_rot13_unwrap(&current);
        steps.push(ReverseReport {
            level: InvokeObfuscationLevel::String,
            transformations: vec!["rot13-unwrap".to_owned()],
            output: current.clone(),
        });
    }
    if REVERSE_TECH.is_match(&current) {
        let unwrapped: String = unwrap_array_reverse(&current);
        if unwrapped != current {
            steps.push(ReverseReport {
                level: InvokeObfuscationLevel::String,
                transformations: vec!["unwrap-array-reverse".to_owned()],
                output: unwrapped.clone(),
            });
            current = unwrapped;
        }
    }
    let string_pass: ReverseReport = reverse_string(&current);
    if !string_pass.transformations.is_empty() {
        current = string_pass.output.clone();
        steps.push(string_pass);
    }
    let tok_pass: ReverseReport = reverse_token(&current);
    if !tok_pass.transformations.is_empty() {
        current = tok_pass.output.clone();
        steps.push(tok_pass);
    }
    InvokeStealthReport {
        steps,
        output: current,
    }
}

fn apply_rot13_unwrap(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len());
    for c in s.chars() {
        out.push(match c {
            'a'..='z' => char::from(((c as u8 - b'a' + 13) % 26) + b'a'),
            'A'..='Z' => char::from(((c as u8 - b'A' + 13) % 26) + b'A'),
            _ => c,
        });
    }
    out
}

fn unwrap_array_reverse(s: &str) -> String {
    REVERSE_TECH
        .replace_all(s, |c: &regex::Captures<'_>| {
            let v: &str = c.get(1).map(|m: regex::Match<'_>| m.as_str()).unwrap_or("");
            format!("${v}")
        })
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rot13_round_trip() {
        let r: InvokeStealthReport = reverse_invoke_stealth("# ROT13 marker\nUryyb");
        assert!(r.output.contains("Hello"));
    }

    #[test]
    fn array_reverse_unwrapped() {
        let r: InvokeStealthReport = reverse_invoke_stealth("[Array]::Reverse($payload); $payload");
        assert!(r.output.contains("$payload"));
        assert!(!r.output.contains("Reverse"));
    }
}
