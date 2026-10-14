use std::collections::BTreeMap;

use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::{Parsed, parse_module};

use super::python_obfuscator_junk::clean_inner_source;
use super::replace_identifier;
use crate::error::Result;
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct PythonObfuscatorPypiPass;

const SIDECAR_TAG: &str = "# python-obfuscator-pypi-rename-map: ";
const BANNER: &str = "# python-obfuscator (PyPI, AST-based)";
const JUNK_LITERAL_LETTERS: usize = 79;

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
        let junk_literal: bool = has_junk_letter_literal(text);
        let real: bool = exec_string_head && (hex_literal || junk_literal);
        let mut markers: Vec<String> = Vec::new();
        if banner {
            markers.push("python-obfuscator-banner".to_owned());
        }
        if exec_string_head && hex_literal {
            markers.push("exec-string-with-bytes-fromhex".to_owned());
        }
        if exec_string_head && junk_literal {
            markers.push("exec-string-with-junk-letter-literal".to_owned());
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

fn has_junk_letter_literal(text: &str) -> bool {
    text.match_indices("= ").any(|(at, _): (usize, &str)| {
        let rest: &[u8] = text.as_bytes().get(at + 2..).unwrap_or_default();
        let rest: &[u8] = rest.strip_prefix(b"\\").unwrap_or(rest);
        let Some(body): Option<&[u8]> = rest.strip_prefix(b"'") else {
            return false;
        };
        let letters: usize = body
            .iter()
            .take_while(|b: &&u8| b.is_ascii_alphabetic())
            .count();
        let tail: &[u8] = body.get(letters..).unwrap_or_default();
        let tail: &[u8] = tail.strip_prefix(b"\\").unwrap_or(tail);
        letters == JUNK_LITERAL_LETTERS && tail.starts_with(b"'")
    })
}

fn peel_real_exec(id: Obfuscator, inner: &str) -> PeelOutcome {
    let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
    diagnostics.insert(
        "inner_line_count".to_owned(),
        inner.lines().count().to_string(),
    );
    let mut stages: Vec<String> = vec![
        "exec-string-detect".to_owned(),
        "string-literal-unescape".to_owned(),
        "exec-unwrap".to_owned(),
    ];
    let mut lossy_notes: Vec<String> = vec![
        "python-obfuscator renames identifiers to random names and keeps no mapping in the file, so renamed names stay as the tool wrote them.".to_owned(),
    ];
    let recovered_source: String = match clean_inner_source(inner) {
        Ok((cleaned, stats)) => {
            stages.extend([
                "fromhex-constant-fold".to_owned(),
                "unreachable-tail-removal".to_owned(),
                "junk-assignment-removal".to_owned(),
            ]);
            diagnostics.insert(
                "fromhex_constants_folded".to_owned(),
                stats.hex_constants_folded.to_string(),
            );
            diagnostics.insert(
                "unreachable_statements_removed".to_owned(),
                stats.unreachable_removed.to_string(),
            );
            diagnostics.insert(
                "junk_assignments_removed".to_owned(),
                stats.junk_assignments_removed.to_string(),
            );
            if stats.introspection_blocked {
                lossy_notes.push("the program reads its own namespace (globals, locals, vars, dir, eval or exec), so junk assignments were kept rather than risk removing a name it looks up.".to_owned());
            }
            cleaned
        }
        Err(error) => {
            lossy_notes.push(format!(
                "the unwrapped source does not parse, so junk assignments and bytes.fromhex constants were left in place: {error}"
            ));
            inner.to_owned()
        }
    };
    PeelOutcome {
        obfuscator: id,
        stages_applied: stages,
        recovered_source,
        confidence: 0.85,
        quality: Quality::Partial,
        lossy_notes,
        diagnostics,
    }
}

fn unwrap_exec_string(text: &str) -> Option<String> {
    let parsed: Parsed<ModModule> = parse_module(text).ok()?;
    let [Stmt::Expr(statement)] = parsed.syntax().body.as_slice() else {
        return None;
    };
    let Expr::Call(call) = statement.value.as_ref() else {
        return None;
    };
    let Expr::Name(callee) = call.func.as_ref() else {
        return None;
    };
    if callee.id.as_str() != "exec" || !call.arguments.keywords.is_empty() {
        return None;
    }
    let [Expr::StringLiteral(literal)] = call.arguments.args.as_ref() else {
        return None;
    };
    Some(literal.value.to_str().to_owned())
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
    fn exec_unwrap_decodes_every_python_escape() {
        let inner: Option<String> = unwrap_exec_string(r#"exec("print('A\x42é 日本')\n")"#);
        assert_eq!(inner.as_deref(), Some("print('ABé 日本')\n"));
    }

    #[test]
    fn non_ascii_text_around_a_renamed_identifier_survives_intact() {
        let text: &str = "café = \"naïve 日本 😀\"\nprint(café, O0O)\n";
        let rewritten: String = replace_identifier(text, "O0O", "total");
        assert_eq!(rewritten, "café = \"naïve 日本 😀\"\nprint(café, total)\n");
    }
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
