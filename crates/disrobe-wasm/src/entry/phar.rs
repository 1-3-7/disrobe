use disrobe_pass_php::{PharArchive, PharCompression, PharEntry, extract_phar_entry, parse_phar};
use serde::Serialize;

const MAX_ENTRIES: usize = 4096;
const MAX_NAME_BYTES: usize = 1024 * 1024;
const MAX_MEMBER_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Serialize)]
struct PharMember {
    index: usize,
    extractable: bool,
    #[serde(flatten)]
    entry: PharEntry,
}

#[derive(Debug, Serialize)]
pub struct PharResult {
    ok: bool,
    format: &'static str,
    api_version: u16,
    global_flags: u32,
    metadata_bytes: usize,
    member_limit_bytes: usize,
    entries: Vec<PharMember>,
}

const fn member_size(entry: &PharEntry) -> usize {
    match entry.compression {
        PharCompression::None => entry.stored_size as usize,
        PharCompression::Deflate | PharCompression::Bzip2 => entry.uncompressed_size as usize,
    }
}

fn archive(bytes: &[u8]) -> Result<PharArchive, String> {
    let archive: PharArchive = parse_phar(bytes)
        .map_err(|error: disrobe_pass_php::Error| format!("PHAR archive: {error}"))?;
    let count_bytes: [u8; 4] = bytes
        .get(archive.manifest_offset..)
        .and_then(|tail: &[u8]| tail.get(4..8))
        .and_then(|count: &[u8]| count.try_into().ok())
        .ok_or_else(|| "PHAR archive: missing member count".to_string())?;
    if u32::from_le_bytes(count_bytes) as usize != archive.entries.len() {
        return Err("PHAR archive: duplicate or colliding member names are ambiguous".to_string());
    }
    if archive.entries.len() > MAX_ENTRIES {
        return Err("PHAR archive: the playground supports up to 4096 members; use the CLI for this archive".to_string());
    }
    let name_bytes: usize = archive.entries.keys().map(String::len).sum();
    if name_bytes > MAX_NAME_BYTES {
        return Err("PHAR archive: member names exceed the 1 MiB browser limit".to_string());
    }
    Ok(archive)
}

pub fn list(bytes: &[u8]) -> Result<PharResult, String> {
    let archive: PharArchive = archive(bytes)?;
    Ok(PharResult {
        ok: true,
        format: "phar",
        api_version: archive.api_version,
        global_flags: archive.global_flags,
        metadata_bytes: archive.metadata.len(),
        member_limit_bytes: MAX_MEMBER_BYTES,
        entries: archive
            .entries
            .into_values()
            .enumerate()
            .map(|(index, entry): (usize, PharEntry)| PharMember {
                index,
                extractable: member_size(&entry) <= MAX_MEMBER_BYTES,
                entry,
            })
            .collect(),
    })
}

pub fn extract(bytes: &[u8], index: u32) -> Result<Vec<u8>, String> {
    let archive: PharArchive = archive(bytes)?;
    let entry: &PharEntry = archive
        .entries
        .values()
        .nth(index as usize)
        .ok_or_else(|| "PHAR archive: selected member is out of range".to_string())?;
    if member_size(entry) > MAX_MEMBER_BYTES {
        return Err(
            "PHAR archive: selected member exceeds 32 MiB; use the CLI to extract it".to_string(),
        );
    }
    let output: Vec<u8> = extract_phar_entry(&archive, bytes, &entry.name)
        .map_err(|error: disrobe_pass_php::Error| format!("PHAR member: {error}"))?;
    if output.len() > MAX_MEMBER_BYTES {
        return Err("PHAR archive: extracted member exceeds the 32 MiB browser limit".to_string());
    }
    Ok(output)
}
