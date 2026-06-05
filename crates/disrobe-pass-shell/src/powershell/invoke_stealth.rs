use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use regex::Regex;
use serde::Serialize;

use super::invoke_obfuscation::{
    InvokeObfuscationLevel, ReverseReport, reverse_string, reverse_token,
};

#[derive(Debug, Clone, Serialize)]
pub struct InvokeStealthReport {
    pub steps: Vec<ReverseReport>,
    pub decoded_payloads: usize,
    pub output: String,
}

static ROT13: LazyLock<Regex> = LazyLock::new(|| crate::regex_util::safe_regex(r"(?i)ROT13"));

static REVERSE_TECH: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(r#"\[\s*[Aa]rray\s*\]::Reverse\s*\(\s*\$([A-Za-z0-9_]+)\s*\)"#)
});

static B64_STRING_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r#"['"]([A-Za-z0-9+/=]{8,})['"]"#));

#[must_use]
pub fn reverse_invoke_stealth(input: &str) -> InvokeStealthReport {
    let mut steps: Vec<ReverseReport> = Vec::new();
    let mut current: String = input.to_owned();
    let mut decoded_payloads: usize = 0;
    if ROT13.is_match(&current) {
        current = apply_rot13_unwrap(&current);
        steps.push(ReverseReport {
            level: InvokeObfuscationLevel::String,
            transformations: vec!["rot13-unwrap".to_owned()],
            output: current.clone(),
        });
    }
    let stealth_payloads: Vec<String> = decode_reverse_b64_payloads(&current);
    if !stealth_payloads.is_empty() {
        decoded_payloads = stealth_payloads.len();
        let recovered: String = stealth_payloads.join("\n");
        steps.push(ReverseReport {
            level: InvokeObfuscationLevel::String,
            transformations: vec!["reverse-b64-decode".to_owned()],
            output: recovered.clone(),
        });
        current = recovered;
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
        decoded_payloads,
        output: current,
    }
}

/// Decode every `Invoke-Stealth` `ReverseB64` payload (reversed base64 via `[array]::Reverse`).
fn decode_reverse_b64_payloads(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for marker in REVERSE_TECH.find_iter(s) {
        let preceding: &str = &s[..marker.start()];
        let Some(literal): Option<regex::Match<'_>> =
            B64_STRING_LITERAL.find_iter(preceding).last()
        else {
            continue;
        };
        let raw: &str = literal
            .as_str()
            .trim_matches(|c: char| c == '\'' || c == '"');
        if let Some(plaintext) = reverse_then_b64_decode(raw)
            && !out.contains(&plaintext)
        {
            out.push(plaintext);
        }
    }
    out
}

fn reverse_then_b64_decode(literal: &str) -> Option<String> {
    let reversed: String = literal.chars().rev().collect::<String>();
    let stripped: String = reversed.trim_end_matches('=').to_owned();
    let padded: String = pad_base64(&stripped);
    let bytes: Vec<u8> = BASE64_STD.decode(&padded).ok()?;
    let text: String = String::from_utf8(bytes).ok()?;
    Some(text.trim_end_matches(['\r', '\n']).to_owned())
}

fn pad_base64(s: &str) -> String {
    match s.len() % 4 {
        0 => s.to_owned(),
        1 => s[..s.len() - 1].to_owned(),
        2 => format!("{s}=="),
        _ => format!("{s}="),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rot13_round_trip() {
        let r: InvokeStealthReport = reverse_invoke_stealth("# ROT13 marker\nUryyb");
        assert!(r.output.contains("Hello"));
    }

    #[test]
    fn reverse_b64_decodes_payload_to_plaintext() {
        let plaintext: &str = "Write-Host \"hello world\"";
        let b64: String = BASE64_STD.encode(plaintext);
        let reversed: String = b64.chars().rev().collect();
        let src: String = format!(
            "$best64code = \"{reversed}\" ; $base64 = $best64code.ToCharArray() ; [array]::Reverse($base64) ; $Stripped = -join $base64 ; [System.Convert]::FromBase64String($Stripped)"
        );
        let r: InvokeStealthReport = reverse_invoke_stealth(&src);
        assert!(r.decoded_payloads >= 1, "must decode at least one payload");
        assert!(
            r.output.contains("Write-Host \"hello world\""),
            "decoded output: {}",
            r.output
        );
    }
}
