use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use disrobe_bytes::ByteReader;

use crate::container::ContainerKind;
use crate::error::{Error, Result};
use crate::extract::{
    EntryCompression, ExtractedEntry, ExtractedEntryOrigin, ExtractionResult, QuotaSummary,
};
use crate::quota::{
    ABSOLUTE_MAX_ENTRIES, ExtractionQuota, QuotaGuard, QuotaReport, prepare_entry_path,
    sanitize_entry_path,
};

const EVB_MAGIC: &[u8; 4] = b"EVB\0";
const PE_SIGNATURE: &[u8; 4] = b"PE\0\0";
const PE32_MACHINE: u16 = 0x014c;
const PE32_OPTIONAL_MAGIC: u16 = 0x010b;
const PE_SECTION_LIMIT: usize = 96;
const PE_SECTION_HEADER_LEN: usize = 40;
const PACK_HEADER_REMAINDER: usize = 60;
const NODE_PREFIX_REMAINDER: usize = 8;
const FOLDER_METADATA_LEN: usize = 25;
const FILE_PREFIX_LEN: usize = 2;
const FILE_FLAGS_LEN: usize = 4;
const FILE_TIMESTAMPS_LEN: usize = 24;
const FILE_METADATA_REMAINDER: usize = 15;
const MAX_MAGIC_CANDIDATES: usize = 64;
const MAX_NAME_UNITS: usize = 2048;
const DEFAULT_FOLDER: &str = "%DEFAULT FOLDER%";
const MALFORMED_LAYOUT: &str = "malformed Enigma Virtual Box x86 built-in file directory";
const ABSENT_DIRECTORY: &str = "Enigma Virtual Box PE has no supported x86 built-in file directory";
const COMPRESSED_MEMBER: &str = "compressed Enigma Virtual Box members require an aPLib decoder";
const NESTING_LIMIT: &str = "Enigma Virtual Box directory nesting exceeds the supported depth";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnigmaVariant {
    X86BuiltInFileLayout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnigmaEntry {
    pub name: String,
    pub data_offset: usize,
    pub stored_size: u32,
    pub original_size: u32,
}

#[derive(Debug, Clone)]
pub struct EnigmaBundle {
    pub variant: EnigmaVariant,
    pub entries: Vec<EnigmaEntry>,
    pub quota: QuotaReport,
}

#[derive(Debug)]
struct DirectoryFrame {
    path: String,
    remaining: u32,
}

const fn unsupported(reason: &'static str) -> Error {
    Error::UnsupportedContainer(reason)
}

fn read_u16(reader: &mut ByteReader<'_>) -> Result<u16> {
    reader
        .read_u16_le()
        .map_err(|_| unsupported(MALFORMED_LAYOUT))
}

fn read_u32(reader: &mut ByteReader<'_>) -> Result<u32> {
    reader
        .read_u32_le()
        .map_err(|_| unsupported(MALFORMED_LAYOUT))
}

fn skip(reader: &mut ByteReader<'_>, count: usize) -> Result<()> {
    reader
        .skip(count)
        .map_err(|_| unsupported(MALFORMED_LAYOUT))
}

fn seek(reader: &mut ByteReader<'_>, position: usize) -> Result<()> {
    reader
        .seek(position)
        .map_err(|_| unsupported(MALFORMED_LAYOUT))
}

fn read_bytes<'a>(reader: &mut ByteReader<'a>, count: usize) -> Result<&'a [u8]> {
    reader
        .read_bytes(count)
        .map_err(|_| unsupported(MALFORMED_LAYOUT))
}

fn pe_has_enigma_sections(bytes: &[u8]) -> bool {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    if read_bytes(&mut reader, 2).ok() != Some(b"MZ".as_slice()) {
        return false;
    }
    if seek(&mut reader, 0x3c).is_err() {
        return false;
    }
    let Ok(pe_offset_u32): Result<u32> = read_u32(&mut reader) else {
        return false;
    };
    let Ok(pe_offset): std::result::Result<usize, _> = usize::try_from(pe_offset_u32) else {
        return false;
    };
    if seek(&mut reader, pe_offset).is_err()
        || read_bytes(&mut reader, PE_SIGNATURE.len()).ok() != Some(PE_SIGNATURE.as_slice())
    {
        return false;
    }
    let Ok(machine): Result<u16> = read_u16(&mut reader) else {
        return false;
    };
    let Ok(section_count_u16): Result<u16> = read_u16(&mut reader) else {
        return false;
    };
    let section_count: usize = usize::from(section_count_u16);
    if machine != PE32_MACHINE || section_count == 0 || section_count > PE_SECTION_LIMIT {
        return false;
    }
    if skip(&mut reader, 12).is_err() {
        return false;
    }
    let Ok(optional_size_u16): Result<u16> = read_u16(&mut reader) else {
        return false;
    };
    if skip(&mut reader, 2).is_err() {
        return false;
    }
    let optional_offset: usize = reader.position();
    let section_table: usize = match optional_offset.checked_add(usize::from(optional_size_u16)) {
        Some(value) => value,
        None => return false,
    };
    if seek(&mut reader, optional_offset).is_err()
        || read_u16(&mut reader).ok() != Some(PE32_OPTIONAL_MAGIC)
        || seek(&mut reader, section_table).is_err()
    {
        return false;
    }
    let mut enigma1: bool = false;
    let mut enigma2: bool = false;
    for _ in 0..section_count {
        let Ok(name_field): Result<&[u8]> = read_bytes(&mut reader, 8) else {
            return false;
        };
        if skip(&mut reader, 8).is_err() {
            return false;
        }
        let Ok(raw_size_u32): Result<u32> = read_u32(&mut reader) else {
            return false;
        };
        let Ok(raw_offset_u32): Result<u32> = read_u32(&mut reader) else {
            return false;
        };
        if skip(&mut reader, PE_SECTION_HEADER_LEN - 24).is_err() {
            return false;
        }
        let raw_size: usize = match usize::try_from(raw_size_u32) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let raw_offset: usize = match usize::try_from(raw_offset_u32) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let raw_end: usize = match raw_offset.checked_add(raw_size) {
            Some(value) => value,
            None => return false,
        };
        let name_end: usize = name_field
            .iter()
            .position(|byte: &u8| *byte == 0)
            .unwrap_or(name_field.len());
        let name: &[u8] = &name_field[..name_end];
        if name == b".enigma1" {
            enigma1 = raw_size > 0 && raw_end <= bytes.len();
        } else if name == b".enigma2" {
            enigma2 = raw_size > 0 && raw_end <= bytes.len();
        }
    }
    enigma1 && enigma2
}

fn read_utf16_name(reader: &mut ByteReader<'_>, directory_end: usize) -> Result<String> {
    let mut units: Vec<u16> = Vec::new();
    loop {
        if units.len() >= MAX_NAME_UNITS || reader.position() >= directory_end {
            return Err(unsupported(MALFORMED_LAYOUT));
        }
        let unit: u16 = read_u16(reader)?;
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    if units.is_empty() {
        return Err(unsupported(MALFORMED_LAYOUT));
    }
    String::from_utf16(&units).map_err(|_| unsupported(MALFORMED_LAYOUT))
}

fn joined_path(parent: &str, child: &str) -> Result<String> {
    let joined: String = if parent.is_empty() {
        child.to_owned()
    } else {
        format!("{parent}/{child}")
    };
    sanitize_entry_path(&joined)
}

fn windows_path_key(safe_name: &str) -> String {
    safe_name.chars().flat_map(char::to_uppercase).collect()
}

fn admit_output_path(paths: &mut BTreeSet<String>, safe_name: &str) -> Result<()> {
    let key: String = windows_path_key(safe_name);
    if paths.contains(&key) {
        return Err(Error::UnsafeEntryPath(safe_name.to_owned()));
    }
    let mut ancestor: &str = key.as_str();
    loop {
        let split: Option<(&str, &str)> = ancestor.rsplit_once('/');
        let Some((prefix, _)) = split else {
            break;
        };
        if paths.contains(prefix) {
            return Err(Error::UnsafeEntryPath(safe_name.to_owned()));
        }
        ancestor = prefix;
    }
    let descendant_prefix: String = format!("{key}/");
    if paths
        .range(descendant_prefix.clone()..)
        .next()
        .is_some_and(|candidate: &String| candidate.starts_with(&descendant_prefix))
    {
        return Err(Error::UnsafeEntryPath(safe_name.to_owned()));
    }
    let _: bool = paths.insert(key);
    Ok(())
}

fn parse_candidate(
    bytes: &[u8],
    magic_offset: usize,
    quota: Option<ExtractionQuota>,
) -> Result<EnigmaBundle> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    seek(&mut reader, magic_offset)?;
    if read_bytes(&mut reader, EVB_MAGIC.len())? != EVB_MAGIC {
        return Err(unsupported(MALFORMED_LAYOUT));
    }
    skip(&mut reader, PACK_HEADER_REMAINDER)?;
    let main_size_u32: u32 = read_u32(&mut reader)?;
    skip(&mut reader, NODE_PREFIX_REMAINDER)?;
    let main_count: u32 = read_u32(&mut reader)?;
    if main_count == 0 {
        return Err(unsupported(MALFORMED_LAYOUT));
    }
    let main_size: usize =
        usize::try_from(main_size_u32).map_err(|_| unsupported(MALFORMED_LAYOUT))?;
    let directory_end: usize = reader
        .position()
        .checked_add(main_size)
        .and_then(|value: usize| value.checked_sub(12))
        .filter(|value: &usize| *value > reader.position() && *value <= bytes.len())
        .ok_or_else(|| unsupported(MALFORMED_LAYOUT))?;
    let first_node: usize = reader
        .position()
        .checked_sub(1)
        .ok_or_else(|| unsupported(MALFORMED_LAYOUT))?;
    seek(&mut reader, first_node)?;

    let mut frames: Vec<DirectoryFrame> = vec![DirectoryFrame {
        path: String::new(),
        remaining: main_count,
    }];
    let mut entries: Vec<EnigmaEntry> = Vec::new();
    let mut paths: BTreeSet<String> = BTreeSet::new();
    let mut guard: Option<QuotaGuard> = quota.map(QuotaGuard::new);
    let mut data_offset: usize = directory_end;
    let mut nodes_seen: usize = 0;
    let mut metadata_bytes: usize = size_of::<DirectoryFrame>();

    while !frames.is_empty() {
        if frames
            .last()
            .is_some_and(|frame: &DirectoryFrame| frame.remaining == 0)
        {
            frames.pop();
            continue;
        }
        let parent_path: String = {
            let frame: &mut DirectoryFrame = frames
                .last_mut()
                .ok_or_else(|| unsupported(MALFORMED_LAYOUT))?;
            frame.remaining -= 1;
            frame.path.clone()
        };
        nodes_seen = nodes_seen
            .checked_add(1)
            .ok_or_else(|| unsupported(MALFORMED_LAYOUT))?;
        if nodes_seen > ABSOLUTE_MAX_ENTRIES || reader.position() >= directory_end {
            return Err(Error::QuotaExceeded {
                entry: "<enigma-directory>".to_owned(),
                reason: format!("directory node count exceeds cap {ABSOLUTE_MAX_ENTRIES}"),
            });
        }
        let _: u32 = read_u32(&mut reader)?;
        skip(&mut reader, NODE_PREFIX_REMAINDER)?;
        let child_count: u32 = read_u32(&mut reader)?;
        let name: String = read_utf16_name(&mut reader, directory_end)?;
        let node_type: u8 = reader
            .read_u8()
            .map_err(|_| unsupported(MALFORMED_LAYOUT))?;
        match node_type {
            2 => {
                if child_count != 0 {
                    return Err(unsupported(MALFORMED_LAYOUT));
                }
                skip(&mut reader, FILE_PREFIX_LEN)?;
                let original_size: u32 = read_u32(&mut reader)?;
                skip(&mut reader, FILE_FLAGS_LEN)?;
                skip(&mut reader, FILE_TIMESTAMPS_LEN)?;
                skip(&mut reader, FILE_METADATA_REMAINDER)?;
                let stored_size: u32 = read_u32(&mut reader)?;
                if quota.is_some() && original_size != stored_size {
                    return Err(unsupported(COMPRESSED_MEMBER));
                }
                let safe_name: String = joined_path(&parent_path, &name)?;
                admit_output_path(&mut paths, &safe_name)?;
                if let Some(guard) = &mut guard {
                    guard.admit_entry(
                        &safe_name,
                        u64::from(original_size),
                        u64::from(stored_size),
                    )?;
                }
                let retained_bytes: usize = size_of::<EnigmaEntry>()
                    .checked_add(safe_name.len())
                    .ok_or_else(|| unsupported(MALFORMED_LAYOUT))?;
                super::admit_metadata_bytes(
                    &mut metadata_bytes,
                    retained_bytes,
                    super::MAX_CONTAINER_METADATA_BYTES,
                    "<enigma-directory>",
                )?;
                let stored_len: usize =
                    usize::try_from(stored_size).map_err(|_| unsupported(MALFORMED_LAYOUT))?;
                let data_end: usize = data_offset
                    .checked_add(stored_len)
                    .filter(|value: &usize| *value <= bytes.len())
                    .ok_or_else(|| unsupported(MALFORMED_LAYOUT))?;
                entries.push(EnigmaEntry {
                    name: safe_name,
                    data_offset,
                    stored_size,
                    original_size,
                });
                data_offset = data_end;
            }
            3 => {
                skip(&mut reader, FOLDER_METADATA_LEN)?;
                let max_depth: usize = usize::try_from(crate::carve::DEFAULT_MAX_DEPTH)
                    .map_or(10, |value: usize| value);
                if frames.len() > max_depth {
                    return Err(unsupported(NESTING_LIMIT));
                }
                let path: String = if name == DEFAULT_FOLDER {
                    parent_path
                } else {
                    joined_path(&parent_path, &name)?
                };
                let retained_bytes: usize = size_of::<DirectoryFrame>()
                    .checked_add(path.len())
                    .ok_or_else(|| unsupported(MALFORMED_LAYOUT))?;
                super::admit_metadata_bytes(
                    &mut metadata_bytes,
                    retained_bytes,
                    super::MAX_CONTAINER_METADATA_BYTES,
                    "<enigma-directory>",
                )?;
                frames.push(DirectoryFrame {
                    path,
                    remaining: child_count,
                });
            }
            _ => return Err(unsupported(MALFORMED_LAYOUT)),
        }
        if reader.position() > directory_end {
            return Err(unsupported(MALFORMED_LAYOUT));
        }
    }
    if entries.is_empty() {
        return Err(unsupported(ABSENT_DIRECTORY));
    }
    let padding_len: usize = directory_end
        .checked_sub(reader.position())
        .ok_or_else(|| unsupported(MALFORMED_LAYOUT))?;
    if read_bytes(&mut reader, padding_len)?
        .iter()
        .any(|byte: &u8| *byte != 0)
    {
        return Err(unsupported(MALFORMED_LAYOUT));
    }
    Ok(EnigmaBundle {
        variant: EnigmaVariant::X86BuiltInFileLayout,
        entries,
        quota: guard.map_or_else(QuotaReport::default, |value: QuotaGuard| *value.report()),
    })
}

#[must_use]
pub fn detect_enigma_virtual_box(bytes: &[u8]) -> bool {
    if !pe_has_enigma_sections(bytes) {
        return false;
    }
    memchr::memmem::find_iter(bytes, EVB_MAGIC)
        .take(MAX_MAGIC_CANDIDATES)
        .any(|magic_offset: usize| parse_candidate(bytes, magic_offset, None).is_ok())
}

pub fn parse_enigma_virtual_box(bytes: &[u8], quota: ExtractionQuota) -> Result<EnigmaBundle> {
    if !pe_has_enigma_sections(bytes) {
        return Err(unsupported(ABSENT_DIRECTORY));
    }
    let mut first_structural_error: Option<Error> = None;
    let mut candidate_count: usize = 0;
    for magic_offset in memchr::memmem::find_iter(bytes, EVB_MAGIC) {
        candidate_count += 1;
        if candidate_count > MAX_MAGIC_CANDIDATES {
            return Err(unsupported(MALFORMED_LAYOUT));
        }
        match parse_candidate(bytes, magic_offset, None) {
            Ok(_) => return parse_candidate(bytes, magic_offset, Some(quota)),
            Err(error) if first_structural_error.is_none() => {
                first_structural_error = Some(error);
            }
            Err(_) => {}
        }
    }
    Err(first_structural_error.unwrap_or_else(|| unsupported(ABSENT_DIRECTORY)))
}

pub fn enigma_member_bytes<'a>(bytes: &'a [u8], entry: &EnigmaEntry) -> Result<&'a [u8]> {
    let size: usize =
        usize::try_from(entry.stored_size).map_err(|_| unsupported(MALFORMED_LAYOUT))?;
    let end: usize = entry
        .data_offset
        .checked_add(size)
        .ok_or_else(|| unsupported(MALFORMED_LAYOUT))?;
    bytes
        .get(entry.data_offset..end)
        .ok_or_else(|| unsupported(MALFORMED_LAYOUT))
}

pub fn extract_enigma_virtual_box(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let bundle: EnigmaBundle = parse_enigma_virtual_box(bytes, quota)?;
    let mut entries: Vec<ExtractedEntry> = Vec::with_capacity(bundle.entries.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    for entry in &bundle.entries {
        let member: &[u8] = enigma_member_bytes(bytes, entry)?;
        let disk_path: PathBuf = prepare_entry_path(out_dir, &entry.name)?;
        std::fs::write(&disk_path, member)?;
        encoding.insert(entry.name.clone(), EntryCompression::Stored);
        entries.push(ExtractedEntry {
            origin: ExtractedEntryOrigin::ArchiveMember,
            name: entry.name.clone(),
            disk_path: Some(disk_path),
            uncompressed_size: u64::from(entry.original_size),
            compressed_size: u64::from(entry.stored_size),
            compression: EntryCompression::Stored,
            is_executable: false,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::EnigmaVirtualBox,
        entries,
        encoding,
        integrity_violations: Vec::new(),
        quota: QuotaSummary::from(&bundle.quota),
    })
}
