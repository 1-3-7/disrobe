use std::collections::BTreeMap;

use crate::ast_eval::{EvalReport, evaluate_source};
use crate::error::Result;
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct ManglifyPass;

const SIDECAR_PREFIX: &str = "# manglify-symbol-map: ";
const BANNER: &str = "# Manglify (Python 3.13)";

impl ObfuscatorPass for ManglifyPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::Manglify
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(64 * 1024)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let banner: bool = text.contains("Manglify") || text.contains("__manglify__");
        let upstream_banner: bool =
            text.contains("Manglify Obfuscator") || text.contains("github.com/ImInTheICU/Manglify");
        let o0_idents: usize = count_o0_identifiers(text);
        let intake_idiom: bool = text.contains("class Engine")
            && text.contains("def Intake")
            && text.contains("def Combustion")
            && text.contains("def Exhaust");
        let mut markers: Vec<String> = Vec::new();
        if banner {
            markers.push("manglify-synth-banner".to_owned());
        }
        if upstream_banner {
            markers.push("manglify-upstream-banner".to_owned());
        }
        if o0_idents >= 6 {
            markers.push(format!("manglify-o0-idents:{o0_idents}"));
        }
        if intake_idiom {
            markers.push("manglify-engine-class".to_owned());
        }
        let matched: bool = banner || upstream_banner || (o0_idents >= 6 && intake_idiom);
        let confidence: f32 = if upstream_banner && intake_idiom {
            0.98
        } else if matched {
            0.9
        } else {
            0.0
        };
        DetectReport {
            obfuscator: self.id(),
            matched,
            confidence,
            markers,
        }
    }

    fn peel(&self, source: &[u8]) -> Result<PeelOutcome> {
        let text: String = String::from_utf8_lossy(source).into_owned();
        if text.contains("Manglify Obfuscator") || text.contains("github.com/ImInTheICU/Manglify") {
            return Ok(peel_upstream_partial(self.id(), &text));
        }
        let mut stages: Vec<String> = Vec::new();
        let map: BTreeMap<String, String> = parse_sidecar(&text);
        stages.push("symbol-map-extract".to_owned());
        let stripped: String = strip_metadata(&text);
        stages.push("strip-metadata".to_owned());
        let unrenamed: String = apply_reverse(&stripped, &map);
        stages.push("ast-unrename".to_owned());
        let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
        diagnostics.insert("renamed_symbols".to_owned(), map.len().to_string());
        let quality: Quality = if map.is_empty() {
            Quality::Partial
        } else {
            Quality::Full
        };
        Ok(PeelOutcome {
            obfuscator: self.id(),
            stages_applied: stages,
            recovered_source: unrenamed,
            confidence: if map.is_empty() { 0.6 } else { 0.92 },
            quality,
            lossy_notes: vec![
                "manglify also collapses whitespace; reformat with `ruff format` for golden style"
                    .to_owned(),
            ],
            diagnostics,
        })
    }
}

fn count_o0_identifiers(text: &str) -> usize {
    let bytes: &[u8] = text.as_bytes();
    let mut count: usize = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        let start: usize = i;
        let mut len: usize = 0;
        let mut all_o0: bool = true;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            if bytes[i] != b'O' && bytes[i] != b'0' {
                all_o0 = false;
            }
            i += 1;
            len += 1;
        }
        if all_o0 && len >= 14 {
            count += 1;
            let _ = start;
        }
        if len == 0 {
            i += 1;
        }
    }
    count
}

fn peel_upstream_partial(id: Obfuscator, text: &str) -> PeelOutcome {
    let mut stages: Vec<String> = vec!["upstream-detect".to_owned(), "strip-trailer".to_owned()];
    let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
    diagnostics.insert(
        "o0_identifier_count".to_owned(),
        count_o0_identifiers(text).to_string(),
    );
    let trailer_start: Option<usize> = text.find("class Engine");
    let stripped: String = trailer_start.map_or_else(
        || text.to_owned(),
        |i: usize| text[..i].trim_end().to_owned() + "\n",
    );
    let (ast_folded, ast_report, ast_ok): (String, EvalReport, bool) =
        match evaluate_source(&stripped) {
            Ok((s, r)) => {
                stages.push("ast-eval".to_owned());
                let ok: bool = r.exprs_folded > 0 || r.bindings_learned > 0;
                (s, r, ok)
            }
            Err(_) => (stripped.clone(), EvalReport::default(), false),
        };
    diagnostics.insert(
        "ast_exprs_folded".to_owned(),
        ast_report.exprs_folded.to_string(),
    );
    diagnostics.insert(
        "ast_bindings_learned".to_owned(),
        ast_report.bindings_learned.to_string(),
    );
    diagnostics.insert(
        "ast_bindings_skipped_dynamic".to_owned(),
        ast_report.bindings_skipped_dynamic.to_string(),
    );
    let (quality, confidence, notes): (Quality, f32, Vec<String>) = if ast_ok {
        (
            Quality::Full,
            0.85,
            vec!["Manglify AST evaluator folded octal-escape string literals and constant exprs after trailer strip".to_owned()],
        )
    } else {
        (
            Quality::Partial,
            0.5,
            vec!["Manglify AST evaluator found no foldable expressions; chunked-dict + lambda decoder remains intact for downstream inspection".to_owned()],
        )
    };
    PeelOutcome {
        obfuscator: id,
        stages_applied: stages,
        recovered_source: ast_folded,
        confidence,
        quality,
        lossy_notes: notes,
        diagnostics,
    }
}

fn parse_sidecar(text: &str) -> BTreeMap<String, String> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        let Some(rest): Option<&str> = line.strip_prefix(SIDECAR_PREFIX) else {
            continue;
        };
        for pair in rest.split(';') {
            let trimmed: &str = pair.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((m, o)) = trimmed.split_once('=') {
                map.insert(m.trim().to_owned(), o.trim().to_owned());
            }
        }
    }
    map
}

fn strip_metadata(text: &str) -> String {
    let mut out: String = String::with_capacity(text.len());
    for line in text.lines() {
        if line.starts_with(SIDECAR_PREFIX)
            || line.starts_with(BANNER)
            || line.starts_with("__manglify__")
        {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn apply_reverse(text: &str, map: &BTreeMap<String, String>) -> String {
    if map.is_empty() {
        return text.to_owned();
    }
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by_key(|k: &&String| core::cmp::Reverse(k.len()));
    let mut out: String = text.to_owned();
    for k in keys {
        let v: &String = match map.get(k) {
            Some(s) => s,
            None => continue,
        };
        out = replace_identifier(&out, k, v);
    }
    out
}

fn replace_identifier(text: &str, needle: &str, replacement: &str) -> String {
    let bytes: &[u8] = text.as_bytes();
    let n: &[u8] = needle.as_bytes();
    if n.is_empty() {
        return text.to_owned();
    }
    let mut out: String = String::with_capacity(text.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        if i + n.len() <= bytes.len()
            && &bytes[i..i + n.len()] == n
            && boundary(bytes, i)
            && boundary(bytes, i + n.len())
        {
            out.push_str(replacement);
            i += n.len();
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn boundary(bytes: &[u8], pos: usize) -> bool {
    if pos == 0 || pos == bytes.len() {
        return true;
    }
    let c: u8 = if pos == 0 { bytes[pos] } else { bytes[pos - 1] };
    !(c.is_ascii_alphanumeric() || c == b'_')
}

#[must_use]
pub fn bake(source: &str) -> String {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    let mut renamed: String = source.to_owned();
    for (idx, ident) in collect_idents(source).into_iter().enumerate() {
        let mangled: String = format!("m{idx:03}");
        renamed = replace_identifier(&renamed, &ident, &mangled);
        map.insert(mangled, ident);
    }
    let sidecar: String = map
        .iter()
        .map(|(k, v): (&String, &String)| format!("{k}={v}"))
        .collect::<Vec<String>>()
        .join("; ");
    format!("{BANNER}\n__manglify__ = '0.3'\n{SIDECAR_PREFIX}{sidecar}\n{renamed}")
}

fn collect_idents(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in source.lines() {
        let trimmed: &str = line.trim_start();
        for prefix in ["def ", "class ", "async def "] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                let end: usize = rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(rest.len());
                let ident: &str = &rest[..end];
                if !ident.is_empty() && !out.iter().any(|s: &String| s == ident) {
                    out.push(ident.to_owned());
                }
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn manglify_roundtrip() {
        let original: &str =
            "def calculate(x):\n    return x * 2\n\ndef double(y):\n    return calculate(y)\n";
        let obf: String = bake(original);
        assert!(ManglifyPass.detect(obf.as_bytes()).matched);
        let out: PeelOutcome = ManglifyPass.peel(obf.as_bytes()).expect("peel");
        assert!(out.recovered_source.contains("def calculate"));
        assert!(out.recovered_source.contains("def double"));
    }
}
