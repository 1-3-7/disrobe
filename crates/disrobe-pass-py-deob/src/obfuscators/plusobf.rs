use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct PlusObfPass;

const UPSTREAM_BANNER: &str = "# obfuscated with plusobf";

impl ObfuscatorPass for PlusObfPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::PlusObf
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(16 * 1024)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let upstream_banner: bool =
            text.contains(UPSTREAM_BANNER) || text.contains("loolzec/plusobf");
        let exec_chr_signature: bool = text.contains("exec(\"\".join([chr(len(i)) for i in d]))")
            || text.contains("exec(''.join([chr(len(i)) for i in d]))");
        let mut markers: Vec<String> = Vec::new();
        if upstream_banner {
            markers.push("plusobf-upstream-banner".to_owned());
        }
        if exec_chr_signature {
            markers.push("plusobf-exec-chr-len-d".to_owned());
        }
        let matched: bool = upstream_banner || exec_chr_signature;
        let confidence: f32 = if upstream_banner && exec_chr_signature {
            0.98
        } else if matched {
            0.7
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
        let text: &str = std::str::from_utf8(source).map_err(Error::from)?;
        peel_upstream(self.id(), text)
    }
}

fn peel_upstream(id: Obfuscator, text: &str) -> Result<PeelOutcome> {
    let lengths: Vec<usize> = extract_d_list_lengths(text).ok_or_else(|| {
        Error::AstCleanup("plusobf upstream: d=[…] list not parseable".to_owned())
    })?;
    let stages: Vec<String> = vec!["d-list-extract".to_owned(), "chr-of-len".to_owned()];
    let mut recovered: String = String::with_capacity(lengths.len());
    for n in &lengths {
        if let Some(c) = u32::try_from(*n).ok().and_then(char::from_u32) {
            recovered.push(c);
        }
    }
    let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
    diagnostics.insert("char_count".to_owned(), lengths.len().to_string());
    Ok(PeelOutcome {
        obfuscator: id,
        stages_applied: stages,
        recovered_source: recovered,
        confidence: 0.98,
        quality: Quality::Full,
        lossy_notes: Vec::new(),
        diagnostics,
    })
}

fn extract_d_list_lengths(text: &str) -> Option<Vec<usize>> {
    let start: usize = text.find("d=[")?;
    let after: &str = &text[start + 3..];
    let close: usize = after.find("];exec(")?;
    let body: &str = &after[..close];
    let mut lengths: Vec<usize> = Vec::new();
    let mut depth: i32 = 0;
    let mut current_len: usize = 0;
    let mut in_str: bool = false;
    let mut quote: u8 = 0;
    let bytes: &[u8] = body.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if in_str {
            if b == quote {
                in_str = false;
                lengths.push(current_len);
                current_len = 0;
            } else if b == b'\\' && i + 1 < bytes.len() {
                current_len += 1;
                i += 2;
                continue;
            } else {
                current_len += 1;
            }
        } else if b == b'\'' || b == b'"' {
            in_str = true;
            quote = b;
        } else if b == b'(' || b == b'[' {
            depth += 1;
        } else if b == b')' || b == b']' {
            depth -= 1;
        }
        let _ = depth;
        i += 1;
    }
    if lengths.is_empty() {
        None
    } else {
        Some(lengths)
    }
}

#[must_use]
pub fn bake(source: &str) -> String {
    let mut d_repr: String = String::from("d=[");
    for (i, c) in source.chars().enumerate() {
        if i > 0 {
            d_repr.push_str(", ");
        }
        d_repr.push('\'');
        for _ in 0..(c as u32) {
            d_repr.push('+');
        }
        d_repr.push('\'');
    }
    d_repr.push_str("];exec(\"\".join([chr(len(i)) for i in d]))");
    format!("# coding=utf-8\n{UPSTREAM_BANNER}\n{d_repr}\n")
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn plusobf_roundtrip() {
        let original: &str = "x = [i*i for i in range(5)]\nprint(x)\n";
        let obf: String = bake(original);
        assert!(PlusObfPass.detect(obf.as_bytes()).matched);
        let out: PeelOutcome = PlusObfPass.peel(obf.as_bytes()).expect("peel");
        assert_eq!(out.recovered_source, original);
    }

    #[test]
    fn plusobf_upstream_format_roundtrip() {
        let original: &str = "ab\n";
        let salt: &str = "+";
        let parts: Vec<String> = original
            .bytes()
            .map(|c: u8| salt.repeat(c as usize))
            .collect();
        let mut d_repr: String = String::from("d=[");
        for (i, p) in parts.iter().enumerate() {
            if i > 0 {
                d_repr.push_str(", ");
            }
            d_repr.push('\'');
            d_repr.push_str(p);
            d_repr.push('\'');
        }
        d_repr.push_str("];exec(\"\".join([chr(len(i)) for i in d]))");
        let obf: String = format!("# coding=utf-8\n# obfuscated with plusobf\nd={d_repr}\n");
        let det: DetectReport = PlusObfPass.detect(obf.as_bytes());
        assert!(det.matched, "{det:?}");
        let out: PeelOutcome = PlusObfPass.peel(obf.as_bytes()).expect("peel");
        assert_eq!(out.recovered_source, original);
    }
}
