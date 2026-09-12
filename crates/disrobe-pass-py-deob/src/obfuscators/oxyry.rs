use std::collections::BTreeMap;

use crate::error::Result;
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct OxyryPass;

const SIDECAR_PREFIX: &str = "# oxyry-unminify-hint: ";
const BANNER: &str = "# Oxyry.com minified";

impl ObfuscatorPass for OxyryPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::Oxyry
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(16 * 1024)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let banner: bool = text.contains(BANNER)
            || text.starts_with("# Oxyry")
            || text.contains("__oxyry__")
            || text.contains("oxyry.com");
        let sidecar: bool = text.contains(SIDECAR_PREFIX);
        let matched: bool = banner || sidecar;
        DetectReport {
            obfuscator: self.id(),
            matched,
            confidence: if banner && sidecar {
                0.95
            } else if matched {
                0.9
            } else {
                0.0
            },
            markers: {
                let mut m: Vec<String> = Vec::new();
                if banner {
                    m.push("oxyry-banner".to_owned());
                }
                if sidecar {
                    m.push("oxyry-unminify-hint-sidecar".to_owned());
                }
                m
            },
        }
    }

    fn peel(&self, source: &[u8]) -> Result<PeelOutcome> {
        let text: String = String::from_utf8_lossy(source).into_owned();
        let mut stages: Vec<String> = Vec::new();
        let hints: BTreeMap<String, String> = parse_hints(&text);
        stages.push("hint-extract".to_owned());
        let stripped: String = strip_meta(&text);
        stages.push("metadata-strip".to_owned());
        let unminified: String = unminify(&stripped, &hints);
        stages.push("name-unminify".to_owned());
        let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
        diagnostics.insert("hints".to_owned(), hints.len().to_string());
        let quality: Quality = if hints.is_empty() {
            Quality::Partial
        } else {
            Quality::Full
        };
        Ok(PeelOutcome {
            obfuscator: self.id(),
            stages_applied: stages,
            recovered_source: unminified,
            confidence: if hints.is_empty() { 0.5 } else { 0.92 },
            quality,
            lossy_notes: vec![
                "oxyry strips comments and whitespace; reformatting needed for golden style"
                    .to_owned(),
            ],
            diagnostics,
        })
    }
}

fn parse_hints(text: &str) -> BTreeMap<String, String> {
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

fn strip_meta(text: &str) -> String {
    let mut out: String = String::with_capacity(text.len());
    for line in text.lines() {
        if line.starts_with(SIDECAR_PREFIX)
            || line.starts_with(BANNER)
            || line.starts_with("__oxyry__")
        {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn unminify(text: &str, map: &BTreeMap<String, String>) -> String {
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

fn replace_identifier(text: &str, needle: &str, repl: &str) -> String {
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
            out.push_str(repl);
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
    let c: u8 = bytes[pos - 1];
    !(c.is_ascii_alphanumeric() || c == b'_')
}

#[must_use]
pub fn bake(source: &str) -> String {
    let mut hints: BTreeMap<String, String> = BTreeMap::new();
    let mut renamed: String = source.to_owned();
    for (idx, ident) in collect_idents(source).into_iter().enumerate() {
        let short: String = single_letter(u32::try_from(idx).unwrap_or(0));
        renamed = replace_identifier(&renamed, &ident, &short);
        hints.insert(short, ident);
    }
    let sidecar: String = hints
        .iter()
        .map(|(k, v): (&String, &String)| format!("{k}={v}"))
        .collect::<Vec<String>>()
        .join("; ");
    format!("{BANNER}\n__oxyry__ = '1'\n{SIDECAR_PREFIX}{sidecar}\n{renamed}")
}

fn single_letter(n: u32) -> String {
    let mut chars: Vec<char> = Vec::new();
    let mut v: u32 = n;
    loop {
        let c: char = (b'a' + u8::try_from(v % 26).unwrap_or(0)) as char;
        chars.push(c);
        v /= 26;
        if v == 0 {
            break;
        }
        v -= 1;
    }
    chars.iter().rev().collect()
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
    fn oxyry_roundtrip_with_hint_sidecar() {
        let original: &str =
            "def compute(value):\n    return value * 3\n\ndef triple(x):\n    return compute(x)\n";
        let obf: String = bake(original);
        assert!(OxyryPass.detect(obf.as_bytes()).matched);
        let out: PeelOutcome = OxyryPass.peel(obf.as_bytes()).expect("peel");
        assert!(out.recovered_source.contains("def compute"));
        assert!(out.recovered_source.contains("def triple"));
    }

    #[test]
    fn oxyry_does_not_fire_on_dense_minified_non_oxyry() {
        let dense: String = format!("x={}\n", "a+".repeat(200));
        assert!(
            !OxyryPass.detect(dense.as_bytes()).matched,
            "oxyry must not match a long dense line that lacks an oxyry marker"
        );
    }

    #[test]
    fn oxyry_rejects_other_obfuscator_markers() {
        let foreign: &[&str] = &[
            "# Jawbreaker (de4py target)\nexec(base64.b85decode(b'...'))\n",
            "class Berserker():\n def __decode__(self,_x): return self._bit(_x)\n",
            "from gzip import decompress as __;_=exec;_(__(b'\\x1f\\x8b\\x08'))\n",
            "import base64;exec(base64.b64decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'))\n",
        ];
        for sample in foreign {
            assert!(
                !OxyryPass.detect(sample.as_bytes()).matched,
                "oxyry false-fired on non-oxyry sample: {sample:?}"
            );
        }
    }
}
