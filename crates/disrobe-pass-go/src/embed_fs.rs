use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::binary::{Endian, GoImage, Section};
use crate::embed_digest::{
    EmbedDigestFamily, FamilyResolution, STORED_DIGEST_LEN, StoredDigest, resolve_family,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbedFile {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub preview: String,
    pub digest: String,
    pub digest_verified: bool,
    #[serde(skip)]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbedMap {
    pub header_va: u64,
    pub records_va: u64,
    pub entry_count: u64,
    pub file_count: usize,
    pub directory_count: usize,
    pub digest_family: Option<EmbedDigestFamily>,
    pub digest_family_distinguishable: bool,
    pub verified_files: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbedScanStats {
    pub sections_scanned: u64,
    pub anchors_matched: u64,
    pub anchors_rejected_by_shape: u64,
    pub anchors_rejected_by_records: u64,
    pub maps_capped: bool,
    pub duplicate_names_dropped: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbedReport {
    pub uses_embed_fs: bool,
    pub directives: Vec<String>,
    pub files: Vec<EmbedFile>,
    pub maps: Vec<EmbedMap>,
    pub scan: EmbedScanStats,
}

const EMBED_FS_TYPE: &[u8] = b"embed.FS";
const GO_EMBED_DIRECTIVE: &[u8] = b"//go:embed";
const MAX_DIRECTIVE_TAIL: usize = 256;
const MAX_DIRECTIVES: usize = 4096;

const SLICE_HEADER_WORDS: u64 = 3;
const RECORD_POINTER_WORDS: u64 = 4;
const MAX_EMBED_NAME_LEN: u64 = 4096;
const MAX_EMBED_DATA_LEN: u64 = 64 * 1024 * 1024;
const MAX_MAP_ENTRIES: u64 = 1 << 16;
const MAX_MAPS: usize = 256;
const PREVIEW_BYTES: usize = 64;
const MAX_TOTAL_EMBED_BYTES: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
struct EmbedRecord {
    name: String,
    is_dir: bool,
    data_va: u64,
    data_len: u64,
    stored: StoredDigest,
}

#[must_use]
pub fn extract_embed(image: &GoImage<'_>) -> EmbedReport {
    let uses_embed_fs: bool = image
        .sections
        .iter()
        .any(|section: &Section<'_>| window_contains(section.data, EMBED_FS_TYPE));

    let directives: Vec<String> = collect_directives(image);
    let mut scan: EmbedScanStats = EmbedScanStats::default();
    let discovered: Vec<(EmbedMap, Vec<EmbedRecord>)> = discover_maps(image, &mut scan);

    let mut files: Vec<EmbedFile> = Vec::new();
    let mut maps: Vec<EmbedMap> = Vec::new();
    let mut total_bytes: usize = 0;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (map, records) in discovered {
        for record in records {
            if !seen.insert(record.name.clone()) {
                scan.duplicate_names_dropped = scan.duplicate_names_dropped.saturating_add(1);
                continue;
            }
            files.push(materialize(
                image,
                &record,
                map.digest_family,
                &mut total_bytes,
            ));
        }
        maps.push(map);
    }
    files.sort_by(|left: &EmbedFile, right: &EmbedFile| left.name.cmp(&right.name));

    EmbedReport {
        uses_embed_fs: uses_embed_fs || !files.is_empty(),
        directives,
        files,
        maps,
        scan,
    }
}

fn materialize(
    image: &GoImage<'_>,
    record: &EmbedRecord,
    family: Option<EmbedDigestFamily>,
    total_bytes: &mut usize,
) -> EmbedFile {
    if record.is_dir {
        return EmbedFile {
            name: record.name.clone(),
            size: 0,
            is_dir: true,
            preview: String::new(),
            digest: hex_encode(&record.stored),
            digest_verified: false,
            data: Vec::new(),
        };
    }
    let remaining: usize = MAX_TOTAL_EMBED_BYTES.saturating_sub(*total_bytes);
    let data: Vec<u8> = read_member_bytes(image, record.data_va, record.data_len, remaining);
    *total_bytes = total_bytes.saturating_add(data.len());
    let complete: bool = data.len() as u64 == record.data_len;
    let digest_verified: bool = complete
        && family.is_some_and(|kind: EmbedDigestFamily| kind.verifies(&data, record.stored));
    EmbedFile {
        name: record.name.clone(),
        size: record.data_len,
        is_dir: false,
        preview: preview_of(&data),
        digest: hex_encode(&record.stored),
        digest_verified,
        data,
    }
}

fn discover_maps(
    image: &GoImage<'_>,
    scan: &mut EmbedScanStats,
) -> Vec<(EmbedMap, Vec<EmbedRecord>)> {
    let pointer_size: u64 = u64::from(image.ptr_size());
    if pointer_size != 4 && pointer_size != 8 {
        return Vec::new();
    }
    let stride: u64 = RECORD_POINTER_WORDS * pointer_size + STORED_DIGEST_LEN as u64;
    let header_span: u64 = SLICE_HEADER_WORDS * pointer_size;
    let step: usize = usize::try_from(pointer_size).unwrap_or(8);

    let mut out: Vec<(EmbedMap, Vec<EmbedRecord>)> = Vec::new();
    let mut claimed: BTreeSet<u64> = BTreeSet::new();
    for section in &image.sections {
        if section.address == 0
            || section.data.len() < usize::try_from(header_span).unwrap_or(usize::MAX)
        {
            continue;
        }
        scan.sections_scanned = scan.sections_scanned.saturating_add(1);
        let Some(limit): Option<usize> = section
            .data
            .len()
            .checked_sub(usize::try_from(header_span).unwrap_or(usize::MAX))
        else {
            continue;
        };
        let mut offset: usize = 0;
        while offset <= limit {
            if out.len() >= MAX_MAPS {
                scan.maps_capped = true;
                return out;
            }
            let Some(header_va): Option<u64> = section.address.checked_add(offset as u64) else {
                break;
            };
            let Some(records_va): Option<u64> =
                read_word(section.data, offset, pointer_size, image.endian())
            else {
                offset += step;
                continue;
            };
            if header_va.checked_add(header_span) != Some(records_va) {
                offset += step;
                continue;
            }
            scan.anchors_matched = scan.anchors_matched.saturating_add(1);
            let Some(map): Option<(EmbedMap, Vec<EmbedRecord>)> = read_map(
                image,
                section,
                offset,
                header_va,
                records_va,
                pointer_size,
                stride,
                scan,
            ) else {
                offset += step;
                continue;
            };
            if claimed.insert(map.0.records_va) {
                out.push(map);
            }
            offset += step;
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn read_map(
    image: &GoImage<'_>,
    section: &Section<'_>,
    offset: usize,
    header_va: u64,
    records_va: u64,
    pointer_size: u64,
    stride: u64,
    scan: &mut EmbedScanStats,
) -> Option<(EmbedMap, Vec<EmbedRecord>)> {
    let word: usize = usize::try_from(pointer_size).ok()?;
    let length: u64 = read_word(
        section.data,
        offset.checked_add(word)?,
        pointer_size,
        image.endian(),
    )?;
    let capacity: u64 = read_word(
        section.data,
        offset.checked_add(word.checked_mul(2)?)?,
        pointer_size,
        image.endian(),
    )?;
    if length == 0 || length != capacity || length > MAX_MAP_ENTRIES {
        scan.anchors_rejected_by_shape = scan.anchors_rejected_by_shape.saturating_add(1);
        return None;
    }
    let span_bytes: u64 = length.checked_mul(stride)?;
    let span: usize = usize::try_from(span_bytes).ok()?;
    let body: &[u8] = image.data_at_va(records_va, span)?;

    let mut records: Vec<EmbedRecord> = Vec::with_capacity(usize::try_from(length).ok()?);
    for index in 0..length {
        let start: usize = usize::try_from(index.checked_mul(stride)?).ok()?;
        let record: &[u8] = body.get(start..start.checked_add(usize::try_from(stride).ok()?)?)?;
        let Some(parsed): Option<EmbedRecord> =
            parse_record(image, record, pointer_size, image.endian())
        else {
            scan.anchors_rejected_by_records = scan.anchors_rejected_by_records.saturating_add(1);
            return None;
        };
        records.push(parsed);
    }

    let resolution: Option<FamilyResolution> = resolve_map_family(image, &records);
    let directory_count: usize = records
        .iter()
        .filter(|record: &&EmbedRecord| record.is_dir)
        .count();
    let file_count: usize = records.len().saturating_sub(directory_count);

    Some((
        EmbedMap {
            header_va,
            records_va,
            entry_count: length,
            file_count,
            directory_count,
            digest_family: resolution.map(|found: FamilyResolution| found.family),
            digest_family_distinguishable: resolution
                .is_some_and(|found: FamilyResolution| found.distinguishable),
            verified_files: resolution.map_or(0, |found: FamilyResolution| found.verified),
        },
        records,
    ))
}

fn parse_record(
    image: &GoImage<'_>,
    record: &[u8],
    pointer_size: u64,
    endian: Endian,
) -> Option<EmbedRecord> {
    let word: usize = usize::try_from(pointer_size).ok()?;
    let name_va: u64 = read_word(record, 0, pointer_size, endian)?;
    let name_len: u64 = read_word(record, word, pointer_size, endian)?;
    let data_va: u64 = read_word(record, word.checked_mul(2)?, pointer_size, endian)?;
    let data_len: u64 = read_word(record, word.checked_mul(3)?, pointer_size, endian)?;
    let digest_start: usize = word.checked_mul(4)?;
    let digest_bytes: &[u8] = record.get(digest_start..digest_start + STORED_DIGEST_LEN)?;
    let mut stored: StoredDigest = [0; STORED_DIGEST_LEN];
    stored.copy_from_slice(digest_bytes);

    if name_len == 0 || name_len > MAX_EMBED_NAME_LEN || data_len > MAX_EMBED_DATA_LEN {
        return None;
    }
    let name_bytes: &[u8] = image.data_at_va(name_va, usize::try_from(name_len).ok()?)?;
    let name: &str = std::str::from_utf8(name_bytes).ok()?;
    if !is_clean_embed_path(name) {
        return None;
    }
    let is_dir: bool = name.ends_with('/');
    if is_dir {
        if data_va != 0 || data_len != 0 || stored != [0; STORED_DIGEST_LEN] {
            return None;
        }
    } else {
        if stored == [0; STORED_DIGEST_LEN] {
            return None;
        }
        if data_len > 0
            && image
                .data_at_va(data_va, usize::try_from(data_len).ok()?)
                .is_none()
        {
            return None;
        }
    }

    Some(EmbedRecord {
        name: name.to_owned(),
        is_dir,
        data_va,
        data_len,
        stored,
    })
}

fn resolve_map_family(image: &GoImage<'_>, records: &[EmbedRecord]) -> Option<FamilyResolution> {
    let mut owned: Vec<(Vec<u8>, StoredDigest)> = Vec::new();
    for record in records.iter().filter(|entry: &&EmbedRecord| !entry.is_dir) {
        let Some(data): Option<Vec<u8>> = read_exact_member(image, record) else {
            continue;
        };
        owned.push((data, record.stored));
    }
    let borrowed: Vec<(&[u8], StoredDigest)> = owned
        .iter()
        .map(|(data, stored): &(Vec<u8>, StoredDigest)| (data.as_slice(), *stored))
        .collect();
    resolve_family(&borrowed)
}

fn read_exact_member(image: &GoImage<'_>, record: &EmbedRecord) -> Option<Vec<u8>> {
    let span: usize = usize::try_from(record.data_len).ok()?;
    if span == 0 {
        return Some(Vec::new());
    }
    image.data_at_va(record.data_va, span).map(<[u8]>::to_vec)
}

fn read_word(bytes: &[u8], offset: usize, pointer_size: u64, endian: Endian) -> Option<u64> {
    match pointer_size {
        4 => {
            let raw: &[u8] = bytes.get(offset..offset.checked_add(4)?)?;
            let array: [u8; 4] = raw.try_into().ok()?;
            Some(u64::from(match endian {
                Endian::Little => u32::from_le_bytes(array),
                Endian::Big => u32::from_be_bytes(array),
            }))
        }
        8 => {
            let raw: &[u8] = bytes.get(offset..offset.checked_add(8)?)?;
            let array: [u8; 8] = raw.try_into().ok()?;
            Some(match endian {
                Endian::Little => u64::from_le_bytes(array),
                Endian::Big => u64::from_be_bytes(array),
            })
        }
        _ => None,
    }
}

fn is_clean_embed_path(path: &str) -> bool {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') || path.contains("//") {
        return false;
    }
    if path.len() > usize::try_from(MAX_EMBED_NAME_LEN).unwrap_or(usize::MAX) {
        return false;
    }
    let mut parts: usize = 0;
    for part in path.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." {
            return false;
        }
        if part
            .chars()
            .any(|character: char| character.is_control() || character == ':')
        {
            return false;
        }
        parts += 1;
    }
    parts > 0
}

fn collect_directives(image: &GoImage<'_>) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for section in &image.sections {
        let buffer: &[u8] = section.data;
        let mut index: usize = 0;
        while index + GO_EMBED_DIRECTIVE.len() <= buffer.len() {
            if &buffer[index..index + GO_EMBED_DIRECTIVE.len()] == GO_EMBED_DIRECTIVE {
                let tail_start: usize = index + GO_EMBED_DIRECTIVE.len();
                let tail: &[u8] = &buffer[tail_start..];
                let limit: usize = tail.len().min(MAX_DIRECTIVE_TAIL);
                let end: usize = tail[..limit]
                    .iter()
                    .position(|byte: &u8| *byte == b'\n' || *byte == 0)
                    .unwrap_or(limit);
                if let Ok(line) = std::str::from_utf8(&tail[..end]) {
                    let trimmed: &str = line.trim();
                    if !trimmed.is_empty() && trimmed.chars().all(is_directive_char) {
                        out.insert(trimmed.to_owned());
                    }
                }
                index = tail_start;
            } else {
                index += 1;
            }
            if out.len() >= MAX_DIRECTIVES {
                break;
            }
        }
    }
    out.into_iter().collect()
}

fn preview_of(data: &[u8]) -> String {
    let take: usize = data.len().min(PREVIEW_BYTES);
    if take == 0 {
        return String::new();
    }
    let head: &[u8] = &data[..take];
    std::str::from_utf8(head).map_or_else(|_| hex_encode(head), str::to_owned)
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

fn window_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window: &[u8]| window == needle)
}
