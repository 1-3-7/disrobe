use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::binary::{GoImage, Section};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbedFile {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub preview: String,
    #[serde(skip)]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbedReport {
    pub uses_embed_fs: bool,
    pub directives: Vec<String>,
    pub files: Vec<EmbedFile>,
}

const EMBED_FS_TYPE: &[u8] = b"embed.FS";
const GO_EMBED_DIRECTIVE: &[u8] = b"//go:embed";
const MAX_DIRECTIVE_TAIL: usize = 256;
const MAX_DIRECTIVES: usize = 4096;

const EMBED_FILE_STRIDE: u64 = 48;
const MAX_EMBED_NAME_LEN: u64 = 256;
const MAX_EMBED_DATA_LEN: u64 = 64 * 1024 * 1024;
const MAX_RUN_ENTRIES: usize = 1 << 16;
const PREVIEW_BYTES: usize = 64;
const MAX_TOTAL_EMBED_BYTES: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
struct EmbedEntry {
    name: String,
    data_va: u64,
    data_len: u64,
    is_dir: bool,
}

#[must_use]
pub fn extract_embed(image: &GoImage<'_>) -> EmbedReport {
    let uses_embed_fs: bool = image
        .sections
        .iter()
        .any(|s: &Section<'_>| window_contains(s.data, EMBED_FS_TYPE));

    let directives: Vec<String> = collect_directives(image);
    let files: Vec<EmbedFile> = walk_embed_files(image);

    EmbedReport {
        uses_embed_fs: uses_embed_fs || !files.is_empty(),
        directives,
        files,
    }
}

fn collect_directives(image: &GoImage<'_>) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for sec in &image.sections {
        let buf: &[u8] = sec.data;
        let mut i: usize = 0;
        while i + GO_EMBED_DIRECTIVE.len() <= buf.len() {
            if &buf[i..i + GO_EMBED_DIRECTIVE.len()] == GO_EMBED_DIRECTIVE {
                let tail_start: usize = i + GO_EMBED_DIRECTIVE.len();
                let tail: &[u8] = &buf[tail_start..];
                let limit: usize = tail.len().min(MAX_DIRECTIVE_TAIL);
                let end: usize = tail[..limit]
                    .iter()
                    .position(|b: &u8| *b == b'\n' || *b == 0)
                    .unwrap_or(limit);
                if let Ok(line) = std::str::from_utf8(&tail[..end]) {
                    let trimmed: &str = line.trim();
                    if !trimmed.is_empty() && trimmed.chars().all(is_directive_char) {
                        out.insert(trimmed.to_owned());
                    }
                }
                i = tail_start;
            } else {
                i += 1;
            }
            if out.len() >= MAX_DIRECTIVES {
                break;
            }
        }
    }
    out.into_iter().collect()
}

fn walk_embed_files(image: &GoImage<'_>) -> Vec<EmbedFile> {
    let mut acc: BTreeMap<String, EmbedFile> = BTreeMap::new();
    let mut total_bytes: usize = 0;
    for sec in &image.sections {
        if !is_data_section(&sec.name) {
            continue;
        }
        scan_section_for_runs(image, sec, &mut acc, &mut total_bytes);
    }
    acc.into_values().collect()
}

fn scan_section_for_runs(
    image: &GoImage<'_>,
    sec: &Section<'_>,
    acc: &mut BTreeMap<String, EmbedFile>,
    total_bytes: &mut usize,
) {
    let base: u64 = sec.address;
    let len: u64 = sec.data.len() as u64;
    let mut pos: u64 = 0;
    while pos <= len.saturating_sub(EMBED_FILE_STRIDE) {
        let Some(first_va): Option<u64> = base.checked_add(pos) else {
            break;
        };
        let Some(first): Option<EmbedEntry> = read_embed_entry(image, first_va) else {
            pos += 8;
            continue;
        };
        let mut run: Vec<EmbedEntry> = vec![first];
        let mut k: u64 = pos + EMBED_FILE_STRIDE;
        while k <= len.saturating_sub(EMBED_FILE_STRIDE) && run.len() < MAX_RUN_ENTRIES {
            let Some(entry_va): Option<u64> = base.checked_add(k) else {
                break;
            };
            let Some(entry): Option<EmbedEntry> = read_embed_entry(image, entry_va) else {
                break;
            };
            run.push(entry);
            let Some(next): Option<u64> = k.checked_add(EMBED_FILE_STRIDE) else {
                break;
            };
            k = next;
        }
        if run.len() >= 2 && is_embed_run(&run) {
            for entry in &run {
                let (preview, data): (String, Vec<u8>) = if entry.is_dir {
                    (String::new(), Vec::new())
                } else {
                    let preview: String = read_preview(image, entry.data_va, entry.data_len);
                    let remaining: usize = MAX_TOTAL_EMBED_BYTES.saturating_sub(*total_bytes);
                    let member: Vec<u8> = if remaining == 0 {
                        Vec::new()
                    } else {
                        let bytes: Vec<u8> =
                            read_member_bytes(image, entry.data_va, entry.data_len, remaining);
                        *total_bytes = total_bytes.saturating_add(bytes.len());
                        bytes
                    };
                    (preview, member)
                };
                acc.entry(entry.name.clone()).or_insert_with(|| EmbedFile {
                    name: entry.name.clone(),
                    size: entry.data_len,
                    is_dir: entry.is_dir,
                    preview,
                    data,
                });
            }
            pos = k;
        } else {
            pos += 8;
        }
    }
}

fn read_embed_entry(image: &GoImage<'_>, va: u64) -> Option<EmbedEntry> {
    let name_ptr: u64 = image.read_ptr(va)?;
    let name_len: u64 = image.read_ptr(va.checked_add(8)?)?;
    let data_ptr: u64 = image.read_ptr(va.checked_add(16)?)?;
    let data_len: u64 = image.read_ptr(va.checked_add(24)?)?;
    if name_len == 0 || name_len > MAX_EMBED_NAME_LEN || data_len > MAX_EMBED_DATA_LEN {
        return None;
    }
    let name_bytes: &[u8] = image.data_at_va(name_ptr, usize::try_from(name_len).ok()?)?;
    if !name_bytes.iter().all(|b: &u8| (0x20..0x7f).contains(b)) {
        return None;
    }
    let name: String = std::str::from_utf8(name_bytes).ok()?.to_owned();
    let is_dir: bool = name.ends_with('/') || (data_ptr == 0 && data_len == 0);
    if !is_dir {
        let span: usize = usize::try_from(data_len).ok()?;
        if data_ptr == 0 || image.data_at_va(data_ptr, span.max(1)).is_none() {
            return None;
        }
    }
    Some(EmbedEntry {
        name,
        data_va: data_ptr,
        data_len,
        is_dir,
    })
}

fn is_embed_run(run: &[EmbedEntry]) -> bool {
    let sorted: bool = run
        .windows(2)
        .all(|w: &[EmbedEntry]| w[0].name <= w[1].name);
    if !sorted {
        return false;
    }
    if !run
        .iter()
        .all(|e: &EmbedEntry| is_clean_relative_path(&e.name))
    {
        return false;
    }
    if !run.iter().any(|e: &EmbedEntry| e.name.contains('/')) {
        return false;
    }
    run.iter().any(|e: &EmbedEntry| {
        if e.is_dir || e.data_len == 0 {
            return false;
        }
        let base: &str = e.name.rsplit('/').next().unwrap_or(&e.name);
        base.rfind('.')
            .is_some_and(|dot: usize| dot + 1 < base.len())
    })
}

fn is_clean_relative_path(s: &str) -> bool {
    if s.is_empty() || s.starts_with('/') || s.contains('\\') || s.contains("//") {
        return false;
    }
    let mut has_part: bool = false;
    for part in s.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." {
            return false;
        }
        if !part
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return false;
        }
        has_part = true;
    }
    has_part
}

fn read_preview(image: &GoImage<'_>, data_va: u64, data_len: u64) -> String {
    let take: usize = usize::try_from(data_len.min(PREVIEW_BYTES as u64)).unwrap_or(0);
    if take == 0 {
        return String::new();
    }
    let Some(bytes): Option<&[u8]> = image.data_at_va(data_va, take) else {
        return String::new();
    };
    std::str::from_utf8(bytes).map_or_else(|_| hex_encode(bytes), str::to_owned)
}

fn read_member_bytes(
    image: &GoImage<'_>,
    data_va: u64,
    data_len: u64,
    remaining: usize,
) -> Vec<u8> {
    let Ok(span): std::result::Result<usize, _> = usize::try_from(data_len) else {
        return Vec::new();
    };
    let span: usize = span.min(remaining);
    if span == 0 {
        return Vec::new();
    }
    image
        .data_at_va(data_va, span)
        .map(<[u8]>::to_vec)
        .unwrap_or_default()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let mut out: String = String::with_capacity(bytes.len().saturating_mul(2usize));
    for byte in bytes.iter().copied() {
        out.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
        out.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
    }
    out
}

fn is_data_section(name: &str) -> bool {
    matches!(
        name,
        ".rdata" | ".data" | ".rodata" | ".data.rel.ro" | "__rodata" | "__const" | "__data"
    )
}

const fn is_directive_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '.' | '_'
                | '-'
                | '/'
                | '*'
                | '\\'
                | '@'
                | ' '
                | '"'
                | '\''
                | '{'
                | '}'
                | '!'
                | '['
                | ']'
                | ','
        )
}

#[inline]
fn window_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_relative_path_rejects_absolute_and_garbage() {
        assert!(!is_clean_relative_path("/etc/passwd"));
        assert!(!is_clean_relative_path(""));
        assert!(!is_clean_relative_path("hello world"));
        assert!(!is_clean_relative_path("../secret.txt"));
        assert!(!is_clean_relative_path("assets/../secret.txt"));
        assert!(!is_clean_relative_path("assets//note.txt"));
        assert!(is_clean_relative_path("assets/note.txt"));
        assert!(is_clean_relative_path("assets/"));
    }

    #[test]
    fn embed_run_requires_real_file_with_extension() {
        let dir_only: Vec<EmbedEntry> = vec![
            EmbedEntry {
                name: "assets/".to_owned(),
                data_va: 0,
                data_len: 0,
                is_dir: true,
            },
            EmbedEntry {
                name: "assets/sub/".to_owned(),
                data_va: 0,
                data_len: 0,
                is_dir: true,
            },
        ];
        assert!(!is_embed_run(&dir_only));

        let with_file: Vec<EmbedEntry> = vec![
            EmbedEntry {
                name: "assets/".to_owned(),
                data_va: 0,
                data_len: 0,
                is_dir: true,
            },
            EmbedEntry {
                name: "assets/note.txt".to_owned(),
                data_va: 0x1000,
                data_len: 36,
                is_dir: false,
            },
        ];
        assert!(is_embed_run(&with_file));
    }

    #[test]
    fn embed_run_rejects_unsorted() {
        let unsorted: Vec<EmbedEntry> = vec![
            EmbedEntry {
                name: "z/file.txt".to_owned(),
                data_va: 0x1000,
                data_len: 10,
                is_dir: false,
            },
            EmbedEntry {
                name: "a/file.txt".to_owned(),
                data_va: 0x2000,
                data_len: 10,
                is_dir: false,
            },
        ];
        assert!(!is_embed_run(&unsorted));
    }

    fn flat_image(bytes: &[u8]) -> GoImage<'_> {
        GoImage {
            kind: crate::binary::ImageKind::Elf,
            endian: crate::binary::Endian::Little,
            ptr_size: 8,
            sections: vec![Section {
                name: ".rodata".to_owned(),
                address: 0x1000,
                data: bytes,
            }],
            raw: bytes,
            symbol_addrs: Vec::new(),
            flat: true,
        }
    }

    #[test]
    fn read_member_bytes_caps_at_remaining_budget() {
        let blob: Vec<u8> = vec![0x41u8; 4096];
        let image: GoImage<'_> = flat_image(&blob);
        let full: Vec<u8> = read_member_bytes(&image, 0x1000, 4096, usize::MAX);
        assert_eq!(
            full.len(),
            4096,
            "valid member recovers fully under ample budget"
        );

        let capped: Vec<u8> = read_member_bytes(&image, 0x1000, 4096, 512);
        assert_eq!(
            capped.len(),
            512,
            "declared length is clamped to the remaining budget"
        );

        let exhausted: Vec<u8> = read_member_bytes(&image, 0x1000, 4096, 0);
        assert!(exhausted.is_empty(), "a zero budget materializes no bytes");
    }

    #[test]
    fn declared_huge_member_does_not_materialize_past_remaining() {
        let blob: Vec<u8> = vec![0x42u8; 1024];
        let image: GoImage<'_> = flat_image(&blob);
        let out: Vec<u8> = read_member_bytes(&image, 0x1000, u64::MAX, 256);
        assert!(
            out.len() <= 256,
            "an attacker-declared u64::MAX data_len must never exceed the remaining budget"
        );
    }

    #[test]
    fn embed_entry_field_offsets_do_not_wrap() {
        let mut high: Vec<u8> = Vec::new();
        high.extend_from_slice(&0x100u64.to_le_bytes());
        high.extend_from_slice(&12u64.to_le_bytes());

        let mut low: Vec<u8> = vec![0u8; 0x140];
        low[0..8].copy_from_slice(&0x120u64.to_le_bytes());
        low[8..16].copy_from_slice(&4u64.to_le_bytes());
        low[0x100..0x10c].copy_from_slice(b"assets/a.txt");
        low[0x120..0x124].copy_from_slice(b"data");

        let image: GoImage<'_> = GoImage {
            kind: crate::binary::ImageKind::Elf,
            endian: crate::binary::Endian::Little,
            ptr_size: 8,
            sections: vec![
                Section {
                    name: ".rdata".to_owned(),
                    address: u64::MAX - 16,
                    data: &high,
                },
                Section {
                    name: ".rdata".to_owned(),
                    address: 0,
                    data: &low,
                },
            ],
            raw: &low,
            symbol_addrs: Vec::new(),
            flat: true,
        };

        assert!(read_embed_entry(&image, u64::MAX - 16).is_none());
    }
}
