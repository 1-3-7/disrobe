use std::collections::BTreeMap;

use crate::error::Result;
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct PythonObfuscatorPypiPass;

const SIDECAR_TAG: &str = "# python-obfuscator-pypi-rename-map: ";
const BANNER: &str = "# python-obfuscator (PyPI, AST-based)";

impl ObfuscatorPass for PythonObfuscatorPypiPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::PythonObfuscatorPypi
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(16 * 1024)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let banner: bool =
            text.contains("python-obfuscator") || text.contains("__python_obfuscator__");
        let leading: &str = text.trim_start();
        let exec_string_head: bool =
            leading.starts_with("exec(\"") || leading.starts_with("exec('");
        let hex_literal: bool = text.contains("bytes.fromhex(");
        let real: bool = exec_string_head && hex_literal;
        let mut markers: Vec<String> = Vec::new();
        if banner {
            markers.push("python-obfuscator-banner".to_owned());
        }
        if real {
            markers.push("exec-string-with-bytes-fromhex".to_owned());
        }
        let matched: bool = banner || real;
        let confidence: f32 = if banner {
            0.85
        } else if real {
            0.88
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
        if let Some(inner) = unwrap_exec_string(text.trim_start()) {
            return Ok(peel_real_exec(self.id(), &inner));
        }
        let mut stages: Vec<String> = Vec::new();
        let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
        let rename_map: BTreeMap<String, String> = extract_rename_map(&text);
        stages.push("sidecar-rename-map-extract".to_owned());
        diagnostics.insert("rename_count".to_owned(), rename_map.len().to_string());
        let body: String = strip_metadata(&text);
        stages.push("strip-banner-and-sidecar".to_owned());
        let renamed: String = apply_reverse_rename(&body, &rename_map);
        stages.push("token-level-rename-reverse".to_owned());
        let quality: Quality = if rename_map.is_empty() {
            Quality::Partial
        } else {
            Quality::Full
        };
        Ok(PeelOutcome {
            obfuscator: self.id(),
            stages_applied: stages,
            recovered_source: renamed,
            confidence: if rename_map.is_empty() { 0.55 } else { 0.92 },
            quality,
            lossy_notes: vec!["synthetic sidecar-rename self-test layer; real upstream uses the exec-string-unwrap path".to_owned()],
            diagnostics,
        })
    }
}

/// Real `PyPI` `python-obfuscator` wraps the program as `exec("<source>")` where the source is a
/// mix of junk variable assignments and the original statements (string constants are hidden via
/// `bytes.fromhex(...).decode()`). Unwrapping the `exec` string literal recovers runnable inner
/// source; the surviving junk assignments make this an honest `Quality::Partial` (downstream
/// dead-store/junk passes can prune further).
fn peel_real_exec(id: Obfuscator, inner: &str) -> PeelOutcome {
    let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
    let line_count: usize = inner.lines().count();
    diagnostics.insert("inner_line_count".to_owned(), line_count.to_string());
    diagnostics.insert(
        "fromhex_constants".to_owned(),
        inner.matches("bytes.fromhex(").count().to_string(),
    );
    PeelOutcome {
        obfuscator: id,
        stages_applied: vec![
            "exec-string-detect".to_owned(),
            "string-literal-unescape".to_owned(),
            "exec-unwrap".to_owned(),
        ],
        recovered_source: inner.to_owned(),
        confidence: 0.85,
        quality: Quality::Partial,
        lossy_notes: vec![
            "python-obfuscator (PyPI): exec(\"...\") wrapper unwrapped to runnable inner source. Junk variable assignments remain (run dead-store elimination to prune); string constants stay as bytes.fromhex(...).decode() calls (valid runtime Python).".to_owned(),
        ],
        diagnostics,
    }
}

/// Unwrap a leading `exec("...")` / `exec('...')`, decoding Python string escapes in the literal.
fn unwrap_exec_string(text: &str) -> Option<String> {
    let after: &str = text.strip_prefix("exec(")?;
    let quote: u8 = match after.as_bytes().first()? {
        b'"' => b'"',
        b'\'' => b'\'',
        _ => return None,
    };
    let body: &[u8] = after.as_bytes().get(1..)?;
    let end: usize = scan_string_end(body, quote)?;
    let lit: &str = after.get(1..1 + end)?;
    Some(decode_python_string_escapes(lit))
}

fn scan_string_end(bytes: &[u8], quote: u8) -> Option<usize> {
    let mut i: usize = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            c if c == quote => return Some(i),
            _ => i += 1,
        }
    }
    None
}

fn decode_python_string_escapes(s: &str) -> String {
    let bytes: &[u8] = s.as_bytes();
    let mut out: String = String::with_capacity(s.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' || i + 1 >= bytes.len() {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        match bytes[i + 1] {
            b'n' => {
                out.push('\n');
                i += 2;
            }
            b't' => {
                out.push('\t');
                i += 2;
            }
            b'r' => {
                out.push('\r');
                i += 2;
            }
            b'\\' => {
                out.push('\\');
                i += 2;
            }
            b'\'' => {
                out.push('\'');
                i += 2;
            }
            b'"' => {
                out.push('"');
                i += 2;
            }
            _ => {
                out.push('\\');
                i += 1;
            }
        }
    }
    out
}

fn extract_rename_map(text: &str) -> BTreeMap<String, String> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        let Some(rest): Option<&str> = line.strip_prefix(SIDECAR_TAG) else {
            continue;
        };
        for pair in rest.split(';') {
            let trimmed: &str = pair.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Some((mangled, original)): Option<(&str, &str)> = trimmed.split_once('=') else {
                continue;
            };
            map.insert(mangled.trim().to_owned(), original.trim().to_owned());
        }
    }
    map
}

fn strip_metadata(text: &str) -> String {
    let mut out: String = String::with_capacity(text.len());
    for line in text.lines() {
        if line.starts_with(SIDECAR_TAG)
            || line.starts_with(BANNER)
            || line.starts_with("__python_obfuscator__")
        {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn apply_reverse_rename(text: &str, map: &BTreeMap<String, String>) -> String {
    if map.is_empty() {
        return text.to_owned();
    }
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by_key(|k: &&String| core::cmp::Reverse(k.len()));
    let mut out: String = text.to_owned();
    for k in keys {
        let original: &String = match map.get(k) {
            Some(v) => v,
            None => continue,
        };
        out = replace_identifier(&out, k, original);
    }
    out
}

fn replace_identifier(text: &str, needle: &str, replacement: &str) -> String {
    let bytes: &[u8] = text.as_bytes();
    let n_bytes: &[u8] = needle.as_bytes();
    if n_bytes.is_empty() {
        return text.to_owned();
    }
    let mut out: String = String::with_capacity(text.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        if i + n_bytes.len() <= bytes.len()
            && &bytes[i..i + n_bytes.len()] == n_bytes
            && is_ident_boundary(bytes, i)
            && is_ident_boundary(bytes, i + n_bytes.len())
        {
            out.push_str(replacement);
            i += n_bytes.len();
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn is_ident_boundary(bytes: &[u8], pos: usize) -> bool {
    if pos == 0 || pos == bytes.len() {
        return true;
    }
    let c: u8 = if pos == 0 { bytes[pos] } else { bytes[pos - 1] };
    !(c.is_ascii_alphanumeric() || c == b'_')
}

#[must_use]
pub fn bake(source: &str) -> String {
    let mut renames: BTreeMap<String, String> = BTreeMap::new();
    let mut rewritten: String = source.to_owned();
    for (idx, ident) in collect_def_identifiers(source).into_iter().enumerate() {
        let mangled: String = format!("v_{idx:04}");
        if renames.contains_key(&mangled) {
            continue;
        }
        rewritten = replace_identifier(&rewritten, &ident, &mangled);
        renames.insert(mangled, ident);
    }
    let sidecar: String = renames
        .iter()
        .map(|(k, v): (&String, &String)| format!("{k}={v}"))
        .collect::<Vec<String>>()
        .join("; ");
    format!("{BANNER}\n__python_obfuscator__ = '1'\n{SIDECAR_TAG}{sidecar}\n{rewritten}")
}

fn collect_def_identifiers(source: &str) -> Vec<String> {
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
                break;
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
    fn python_obfuscator_pypi_roundtrip() {
        let original: &str =
            "def alpha(x):\n    return x\n\ndef beta(y):\n    return alpha(y) + 1\n";
        let obf: String = bake(original);
        assert!(PythonObfuscatorPypiPass.detect(obf.as_bytes()).matched);
        let out: PeelOutcome = PythonObfuscatorPypiPass.peel(obf.as_bytes()).expect("peel");
        assert!(out.recovered_source.contains("def alpha"));
        assert!(out.recovered_source.contains("def beta"));
        assert!(out.recovered_source.contains("alpha(y)"));
    }
}
