use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

use super::invoke_obfuscation::{reverse_string, reverse_token};

#[derive(Debug, Clone, Serialize)]
pub struct ChameleonReport {
    pub renamed_variables: usize,
    pub renamed_functions: usize,
    pub output: String,
}

static VAR_DECL: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"\$\{?([A-Za-z_][A-Za-z0-9_]{0,7})\}?\s*="));

static FUNC_DECL: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(r"(?i)\bfunction\s+([A-Za-z_][A-Za-z0-9_\-]*)\b")
});

#[must_use]
pub fn reverse_chameleon(input: &str) -> ChameleonReport {
    let token_pass: String = reverse_token(input).output;
    let string_pass: String = reverse_string(&token_pass).output;
    let mut current: String = string_pass;
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
        let pat: String = format!(r"\$\{{?{orig}\}}?");
        let re: Regex = crate::regex_util::safe_regex(&pat);
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
        let pat: String = format!(r"\b{orig}\b");
        let re: Regex = crate::regex_util::safe_regex(&pat);
        current = re.replace_all(&current, sub.as_str()).into_owned();
    }
    ChameleonReport {
        renamed_variables: var_count,
        renamed_functions: func_count,
        output: current,
    }
}

fn looks_chameleon_mangled(name: &str) -> bool {
    name.len() <= 4
        && name
            .chars()
            .all(|c: char| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
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
}
