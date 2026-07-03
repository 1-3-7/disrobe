use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct XindexObfPass;

const GROUP_LEN: usize = 10;
const HALF_LEN: usize = 5;

impl ObfuscatorPass for XindexObfPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::XindexObf
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(32 * 1024)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let mut markers: Vec<String> = Vec::new();
        let arithmetic_signature: bool = text.contains("[5:]")
            && text.contains("[:5]")
            && (text.contains(".split('|')") || text.contains(".split(\"|\")"));
        let table: Option<&str> = extract_group_table(text);
        if arithmetic_signature {
            markers.push("xindex-chr-subtract-5-5".to_owned());
        }
        if table.is_some() {
            markers.push("xindex-pipe-group-table".to_owned());
        }
        let matched: bool = arithmetic_signature && table.is_some();
        let confidence: f32 = if matched {
            0.95
        } else if arithmetic_signature || table.is_some() {
            0.4
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
        let table: &str = extract_group_table(text)
            .ok_or_else(|| Error::AstCleanup("xindex: pipe-group table not found".to_owned()))?;
        let recovered: String = decode_table(table)
            .ok_or_else(|| Error::AstCleanup("xindex: malformed arithmetic group".to_owned()))?;
        let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
        diagnostics.insert(
            "char_count".to_owned(),
            recovered.chars().count().to_string(),
        );
        Ok(PeelOutcome {
            obfuscator: self.id(),
            stages_applied: vec!["pipe-group-split".to_owned(), "chr-subtract".to_owned()],
            recovered_source: recovered,
            confidence: 0.95,
            quality: Quality::Full,
            lossy_notes: Vec::new(),
            diagnostics,
        })
    }
}

fn extract_group_table(text: &str) -> Option<&str> {
    let mut best: Option<&str> = None;
    let mut best_len: usize = 0;
    let bytes: &[u8] = text.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'\'' || bytes[i] == b'"' {
            let quote: u8 = bytes[i];
            let start: usize = i + 1;
            let mut j: usize = start;
            while j < bytes.len() && bytes[j] != quote {
                j += 1;
            }
            if j <= bytes.len() {
                let candidate: &str = text.get(start..j).unwrap_or("");
                if is_group_table(candidate) && candidate.len() > best_len {
                    best_len = candidate.len();
                    best = Some(candidate);
                }
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    best
}

fn is_group_table(candidate: &str) -> bool {
    if candidate.is_empty() {
        return false;
    }
    let groups: Vec<&str> = candidate.split('|').collect();
    groups.len() >= 2
        && groups
            .iter()
            .all(|g: &&str| g.len() == GROUP_LEN && g.bytes().all(|b: u8| b.is_ascii_digit()))
}

fn decode_table(table: &str) -> Option<String> {
    let mut out: String = String::new();
    for group in table.split('|') {
        if group.len() != GROUP_LEN {
            return None;
        }
        let left: i64 = group.get(..HALF_LEN)?.parse::<i64>().ok()?;
        let right: i64 = group.get(HALF_LEN..)?.parse::<i64>().ok()?;
        let code_point: i64 = right - left;
        let value: u32 = u32::try_from(code_point).ok()?;
        out.push(char::from_u32(value)?);
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub fn bake(source: &str) -> String {
    let table: String = source
        .chars()
        .map(|c: char| {
            let code: u32 = c as u32;
            let base: u32 = 10000;
            format!("{base:05}{:05}", base + code)
        })
        .collect::<Vec<String>>()
        .join("|");
    format!("d='{table}'\nexec(''.join(chr(int(g[5:])-int(g[:5])) for g in d.split('|')))\n")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_and_decodes_xindex() {
        let original: &str = "print('xindex recovered')";
        let obf: String = bake(original);
        let det: DetectReport = XindexObfPass.detect(obf.as_bytes());
        assert!(det.matched, "must detect xindex: {:?}", det.markers);
        let out: PeelOutcome = XindexObfPass.peel(obf.as_bytes()).expect("peel");
        assert_eq!(out.recovered_source, original);
        assert_eq!(out.quality, Quality::Full);
    }

    #[test]
    fn decode_table_rejects_malformed_group() {
        assert!(decode_table("12345").is_none());
        assert!(decode_table("abcde12345").is_none());
    }

    #[test]
    fn rejects_non_xindex() {
        let det: DetectReport = XindexObfPass.detect(b"def main(): return 1");
        assert!(!det.matched);
    }
}
