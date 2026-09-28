use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use lazy_regex::regex;
use regex::Regex;
use serde::Serialize;

use super::invoke_obfuscation::{reverse_string, reverse_token};

const MAX_BASE64_INPUT: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct ChameleonReport {
    pub renamed_variables: usize,
    pub renamed_functions: usize,
    pub decoded_payload: bool,
    pub output: String,
}

static VAR_DECL: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"));

static FUNC_DECL: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"(?i)\bfunction\s+([A-Za-z_][A-Za-z0-9_\-]*)\b"));

static FROMBASE64_LITERAL: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(
        r#"(?i)\[\s*(?:system\.)?convert\s*\]::frombase64string\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)"#
    )
});

static WORD: LazyLock<&'static Regex> = LazyLock::new(|| regex!(r"[A-Za-z][A-Za-z0-9]*"));

const CASE_RANDOMIZED_NAMES: [&str; 20] = [
    "System",
    "Text",
    "Encoding",
    "Convert",
    "FromBase64String",
    "GetString",
    "UTF8",
    "Unicode",
    "ASCII",
    "MemoryStream",
    "Compression",
    "StreamReader",
    "ReadToEnd",
    "WebClient",
    "DownloadString",
    "Invoke",
    "Expression",
    "Object",
    "Write",
    "Host",
];

const MIN_CASE_RANDOMIZED_NAMES: usize = 3;
const MIN_RENAMED_IDENTIFIER_LEN: usize = 32;
const MIN_RENAMED_IDENTIFIER_DIGITS: usize = 3;
const MIN_RENAMED_IDENTIFIERS: usize = 2;

#[must_use]
pub(crate) fn has_chameleon_shape(text: &str) -> bool {
    case_randomized_names(text) >= MIN_CASE_RANDOMIZED_NAMES
        || renamed_identifiers(text) >= MIN_RENAMED_IDENTIFIERS
}

fn case_randomized_names(text: &str) -> usize {
    let mut seen: BTreeSet<&'static str> = BTreeSet::new();
    for word in WORD.find_iter(text) {
        let word: &str = word.as_str();
        let mixed: bool = word.bytes().any(|b: u8| b.is_ascii_lowercase())
            && word.bytes().any(|b: u8| b.is_ascii_uppercase());
        if !mixed {
            continue;
        }
        if let Some(name) = CASE_RANDOMIZED_NAMES
            .iter()
            .find(|name: &&&str| word.eq_ignore_ascii_case(name) && word != **name)
        {
            seen.insert(name);
        }
    }
    seen.len()
}

fn renamed_identifiers(text: &str) -> usize {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for cap in VAR_DECL.captures_iter(text) {
        if let Some(name) = cap.get(1)
            && name.as_str().len() >= MIN_RENAMED_IDENTIFIER_LEN
            && name
                .as_str()
                .bytes()
                .filter(|b: &u8| b.is_ascii_digit())
                .count()
                >= MIN_RENAMED_IDENTIFIER_DIGITS
            && is_long_random_identifier(name.as_str())
        {
            seen.insert(name.as_str());
        }
    }
    seen.len()
}

#[must_use]
pub fn reverse_chameleon(input: &str) -> ChameleonReport {
    let token_pass: String = reverse_token(input).output;
    let string_pass: String = reverse_string(&token_pass).output;
    let mut current: String = string_pass;
    let decoded_payload: bool = match decode_frombase64_payload(&current) {
        Some(plaintext) => {
            current = plaintext;
            true
        }
        None => false,
    };
    let mut var_map: BTreeMap<String, String> = BTreeMap::new();
    for cap in VAR_DECL.captures_iter(&current.clone()) {
        if let Some(name) = cap.get(1) {
            let raw: String = name.as_str().to_owned();
            if looks_chameleon_mangled(&raw) {
                let idx: usize = var_map.len() + 1;
                var_map.entry(raw).or_insert_with(|| format!("v{idx}"));
            }
        }
    }
    let var_count: usize = var_map.len();
    for (orig, sub) in &var_map {
        let pat: String = format!(r"\$\{{?{}\}}?", regex::escape(orig));
        let Ok(re): Result<Regex, regex::Error> = Regex::new(&pat) else {
            continue;
        };
        let replacement: String = format!("${sub}");
        current = re
            .replace_all(&current, regex::NoExpand(replacement.as_str()))
            .into_owned();
    }
    let mut func_map: BTreeMap<String, String> = BTreeMap::new();
    for cap in FUNC_DECL.captures_iter(&current.clone()) {
        if let Some(name) = cap.get(1) {
            let raw: String = name.as_str().to_owned();
            if looks_chameleon_mangled(&raw) {
                let idx: usize = func_map.len() + 1;
                func_map.entry(raw).or_insert_with(|| format!("Func-{idx}"));
            }
        }
    }
    let func_count: usize = func_map.len();
    for (orig, sub) in &func_map {
        let pat: String = format!(r"\b{}\b", regex::escape(orig));
        let Ok(re): Result<Regex, regex::Error> = Regex::new(&pat) else {
            continue;
        };
        current = re.replace_all(&current, sub.as_str()).into_owned();
    }
    ChameleonReport {
        renamed_variables: var_count,
        renamed_functions: func_count,
        decoded_payload,
        output: current,
    }
}

fn decode_frombase64_payload(s: &str) -> Option<String> {
    let cap: regex::Captures<'_> = FROMBASE64_LITERAL.captures(s)?;
    let b64: &str = cap.get(1)?.as_str();
    if b64.len() > MAX_BASE64_INPUT {
        return None;
    }
    let bytes: Vec<u8> = BASE64_STD.decode(b64.trim()).ok()?;
    let text: String = String::from_utf8(bytes).ok()?;
    Some(text.trim_end_matches(['\r', '\n']).to_owned())
}

fn looks_chameleon_mangled(name: &str) -> bool {
    let short_uppercase: bool = name.len() <= 4
        && name
            .chars()
            .all(|c: char| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    short_uppercase || is_long_random_identifier(name)
}

fn is_long_random_identifier(name: &str) -> bool {
    if name.len() < 20 || !name.chars().all(|c: char| c.is_ascii_alphanumeric()) {
        return false;
    }
    let has_lower: bool = name.chars().any(|c: char| c.is_ascii_lowercase());
    let has_upper: bool = name.chars().any(|c: char| c.is_ascii_uppercase());
    let has_digit: bool = name.chars().any(|c: char| c.is_ascii_digit());
    has_lower && has_upper && has_digit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renames_mangled_variables() {
        let src: &str = "$A1 = 1\n$B2 = $A1 + 2\n";
        let r: ChameleonReport = reverse_chameleon(src);
        assert!(r.renamed_variables >= 2);
        assert!(r.output.contains("$v1"));
    }

    #[test]
    fn decodes_frombase64_payload_to_plaintext() {
        let b64: String = BASE64_STD.encode("Write-Host \"hello world\"");
        let src: String = format!(
            "iex([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{b64}')));exit"
        );
        let r: ChameleonReport = reverse_chameleon(&src);
        assert!(r.decoded_payload, "payload must actually decode");
        assert_eq!(r.output, "Write-Host \"hello world\"");
    }

    #[test]
    fn oversized_frombase64_literal_is_not_decoded() {
        let oversized: String = "A".repeat(MAX_BASE64_INPUT + 1);
        let src: String = format!("[Convert]::FromBase64String('{oversized}')");
        let r: ChameleonReport = reverse_chameleon(&src);
        assert!(!r.decoded_payload);
        assert!(r.output.contains("FromBase64String"));
    }
}
