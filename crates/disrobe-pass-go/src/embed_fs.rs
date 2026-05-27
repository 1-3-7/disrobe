use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::binary::GoImage;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbedFile {
    pub name: String,
    pub size: u64,
    pub preview: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbedReport {
    pub files: Vec<EmbedFile>,
    pub strings_with_embed_marker: Vec<String>,
}

pub fn extract_embed(image: &GoImage<'_>) -> EmbedReport {
    let mut files: Vec<EmbedFile> = Vec::new();
    let mut markers: Vec<String> = Vec::new();
    let mut seen: BTreeMap<String, u64> = BTreeMap::new();

    for sec in &image.sections {
        scan_section(sec.data, &mut seen, &mut markers);
    }

    for (name, size) in seen {
        files.push(EmbedFile {
            name,
            size,
            preview: String::new(),
        });
    }
    files.sort_by(|a: &EmbedFile, b: &EmbedFile| a.name.cmp(&b.name));
    markers.sort();
    markers.dedup();

    EmbedReport {
        files,
        strings_with_embed_marker: markers,
    }
}

fn scan_section(buf: &[u8], seen: &mut BTreeMap<String, u64>, markers: &mut Vec<String>) {
    let needle: &[u8] = b"embed.FS";
    let mut i: usize = 0;
    while i + needle.len() <= buf.len() {
        if &buf[i..i + needle.len()] == needle {
            markers.push("embed.FS".to_owned());
        }
        i += 1;
    }
    let go_embed: &[u8] = b"//go:embed";
    let mut j: usize = 0;
    while j + go_embed.len() <= buf.len() {
        if &buf[j..j + go_embed.len()] == go_embed {
            let tail: &[u8] = &buf[j + go_embed.len()..];
            let limit: usize = tail.len().min(120);
            let end: usize = tail
                .iter()
                .position(|b: &u8| *b == b'\n' || *b == 0)
                .unwrap_or(limit);
            if let Ok(s) = std::str::from_utf8(&tail[..end]) {
                for tok in s.split_whitespace() {
                    if !tok.is_empty() && looks_like_embed_name(tok) {
                        seen.entry(tok.to_owned()).or_insert(0);
                    }
                }
            }
        }
        j += 1;
    }
    let embed_marker: &[u8] = b"embedded.txt";
    let mut k: usize = 0;
    while k + embed_marker.len() <= buf.len() {
        if &buf[k..k + embed_marker.len()] == embed_marker {
            seen.entry("embedded.txt".to_owned()).or_insert(0);
        }
        k += 1;
    }
}

fn looks_like_embed_name(tok: &str) -> bool {
    if tok.starts_with('"') || tok.starts_with('\'') {
        return false;
    }
    if tok.is_empty() || tok.len() > 256 {
        return false;
    }
    tok.bytes().all(|b: u8| {
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b'*' | b'\\' | b'@')
    })
}
