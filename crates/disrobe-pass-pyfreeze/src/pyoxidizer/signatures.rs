use serde::{Deserialize, Serialize};

const MARKER_PYEMBED: &[u8] = b"pyembed";
const MARKER_PYOXIDIZER: &[u8] = b"PyOxidizer";
const MARKER_RUNTIME_ANCHOR: &[u8] = b"pyoxidizer_run";
const MARKER_RESOURCES: &[u8] = b"python-stdlib";
const MARKER_INTERPRETER: &[u8] = b"PythonInterpreterConfig";
const BLOB_MAGIC_V3: &[u8] = b"pyembed\x03";
const BLOB_MAGIC_LEGACY: &[u8] = b"pyembed-resources-0";
const MAGIC_PREFIX: &[u8] = b"pyembed";
const MAGIC_LEN: usize = MAGIC_PREFIX.len() + 1;
const MAX_STRUCTURED_VERSION: u8 = 3;

const HEADER_TRAILER_LEN: usize = 1 + 4 + 4 + 4;

const BLOB_END_OF_INDEX: u8 = 0x00;
const BLOB_START_OF_ENTRY: u8 = 0x01;
const BLOB_RESOURCE_FIELD_TYPE: u8 = 0x02;
const BLOB_RAW_PAYLOAD_LENGTH: u8 = 0x03;
const BLOB_INTERIOR_PADDING: u8 = 0x04;
const BLOB_END_OF_ENTRY: u8 = 0xff;

const PADDING_NONE: u8 = 0x01;
const PADDING_NULL: u8 = 0x02;

const RES_END_OF_INDEX: u8 = 0x00;
const RES_START_OF_ENTRY: u8 = 0x01;
const RES_NAME: u8 = 0x03;
const RES_IS_PYTHON_PACKAGE: u8 = 0x04;
const RES_IS_PYTHON_NAMESPACE_PACKAGE: u8 = 0x05;
const RES_IN_MEMORY_SOURCE: u8 = 0x06;
const RES_IN_MEMORY_BYTECODE: u8 = 0x07;
const RES_IN_MEMORY_BYTECODE_OPT1: u8 = 0x08;
const RES_IN_MEMORY_BYTECODE_OPT2: u8 = 0x09;
const RES_IN_MEMORY_EXTENSION_MODULE: u8 = 0x0a;
const RES_IN_MEMORY_RESOURCES_DATA: u8 = 0x0b;
const RES_IN_MEMORY_DISTRIBUTION_RESOURCE: u8 = 0x0c;
const RES_IN_MEMORY_SHARED_LIBRARY: u8 = 0x0d;
const RES_SHARED_LIBRARY_DEPENDENCY_NAMES: u8 = 0x0e;
const RES_RELATIVE_FS_MODULE_SOURCE: u8 = 0x0f;
const RES_RELATIVE_FS_MODULE_BYTECODE: u8 = 0x10;
const RES_RELATIVE_FS_MODULE_BYTECODE_OPT1: u8 = 0x11;
const RES_RELATIVE_FS_MODULE_BYTECODE_OPT2: u8 = 0x12;
const RES_RELATIVE_FS_EXTENSION_MODULE: u8 = 0x13;
const RES_RELATIVE_FS_PACKAGE_RESOURCES: u8 = 0x14;
const RES_RELATIVE_FS_DISTRIBUTION_RESOURCE: u8 = 0x15;
const RES_IS_PYTHON_MODULE: u8 = 0x16;
const RES_IS_PYTHON_BUILTIN_EXTENSION_MODULE: u8 = 0x17;
const RES_IS_PYTHON_FROZEN_MODULE: u8 = 0x18;
const RES_IS_PYTHON_EXTENSION_MODULE: u8 = 0x19;
const RES_IS_SHARED_LIBRARY: u8 = 0x1a;
const RES_IS_UTF8_FILENAME_DATA: u8 = 0x1b;
const RES_FILE_EXECUTABLE: u8 = 0x1c;
const RES_FILE_DATA_EMBEDDED: u8 = 0x1d;
const RES_FILE_DATA_UTF8_RELATIVE_PATH: u8 = 0x1e;
const RES_END_OF_ENTRY: u8 = 0xff;

const RESOURCE_FIELD_SLOTS: usize = 256;
const MAX_BLOB_SLICE: usize = 256 * 1024 * 1024;

#[must_use]
pub fn scan(bytes: &[u8]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let pairs: [(&[u8], &str); 7] = [
        (MARKER_PYEMBED, "pyembed"),
        (MARKER_PYOXIDIZER, "PyOxidizer"),
        (MARKER_RUNTIME_ANCHOR, "pyoxidizer_run"),
        (MARKER_RESOURCES, "python-stdlib"),
        (MARKER_INTERPRETER, "PythonInterpreterConfig"),
        (BLOB_MAGIC_V3, "pyembed-resources-v3"),
        (BLOB_MAGIC_LEGACY, "pyembed-resources-legacy"),
    ];
    for (pat, label) in pairs {
        if contains(bytes, pat) {
            found.push(label.to_owned());
        }
    }
    found
}

#[must_use]
pub fn is_present(markers: &[String]) -> bool {
    let has_runtime: bool = markers.iter().any(|m| {
        matches!(
            m.as_str(),
            "pyembed"
                | "PyOxidizer"
                | "pyoxidizer_run"
                | "pyembed-resources-v3"
                | "pyembed-resources-legacy"
        )
    });
    let has_aux: bool = markers.len() >= 2;
    has_runtime && has_aux
}

#[must_use]
pub fn infer_python_version(bytes: &[u8]) -> (Option<u8>, Option<u8>, Option<String>) {
    let candidates: [(&str, u8, u8); 16] = [
        ("python314.dll", 3u8, 14u8),
        ("python313.dll", 3, 13),
        ("python312.dll", 3, 12),
        ("python311.dll", 3, 11),
        ("python310.dll", 3, 10),
        ("python39.dll", 3, 9),
        ("python38.dll", 3, 8),
        ("python37.dll", 3, 7),
        ("libpython3.14", 3, 14),
        ("libpython3.13", 3, 13),
        ("libpython3.12", 3, 12),
        ("libpython3.11", 3, 11),
        ("libpython3.10", 3, 10),
        ("libpython3.9", 3, 9),
        ("libpython3.8", 3, 8),
        ("libpython3.7", 3, 7),
    ];
    for (needle, major, minor) in candidates {
        if contains(bytes, needle.as_bytes()) {
            return (Some(major), Some(minor), Some(needle.to_owned()));
        }
    }
    (None, None, None)
}

#[must_use]
pub fn extract_resources_blob(bytes: &[u8]) -> Option<&[u8]> {
    if let Some(start) = find(bytes, BLOB_MAGIC_V3) {
        let region: &[u8] = &bytes[start..];
        if let Some(exact_len) = measured_blob_len(region) {
            return Some(&region[..exact_len]);
        }
        let cap: usize = region.len().min(MAX_BLOB_SLICE);
        return Some(&region[..cap]);
    }
    for version in (0..MAX_STRUCTURED_VERSION).rev() {
        let magic: [u8; MAGIC_LEN] = packed_magic(version);
        if let Some(start) = find(bytes, &magic) {
            let region: &[u8] = &bytes[start..];
            if let Some(exact_len) = measured_blob_len(region) {
                return Some(&region[..exact_len]);
            }
        }
    }
    let start: usize = find(bytes, BLOB_MAGIC_LEGACY)?;
    let region: &[u8] = &bytes[start..];
    let cap: usize = region.len().min(MAX_BLOB_SLICE);
    Some(&region[..cap])
}

fn measured_blob_len(region: &[u8]) -> Option<usize> {
    let header: Header = read_header(region)?;
    let sections: Vec<BlobSection> = parse_blob_index(
        region,
        MAGIC_LEN + HEADER_TRAILER_LEN,
        header.blob_index_length,
    )?;
    let total_payload: usize = sections
        .iter()
        .try_fold(0usize, |acc: usize, s: &BlobSection| {
            acc.checked_add(s.raw_payload_length)
        })?;
    let blobs_start: usize = MAGIC_LEN
        .checked_add(HEADER_TRAILER_LEN)?
        .checked_add(header.blob_index_length)?
        .checked_add(header.resources_index_length)?;
    let end: usize = blobs_start.checked_add(total_payload)?;
    if end <= region.len() { Some(end) } else { None }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceTier {
    Source,
    Bytecode,
    BytecodeOpt1,
    BytecodeOpt2,
    Extension,
    Resource,
    Unknown,
}

impl ResourceTier {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Bytecode => "bytecode",
            Self::BytecodeOpt1 => "bytecode-opt-1",
            Self::BytecodeOpt2 => "bytecode-opt-2",
            Self::Extension => "extension",
            Self::Resource => "resource",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedResourceEntry {
    pub tier: ResourceTier,
    pub name: String,
    pub content_offset: usize,
    pub content_len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackedResourcesParse {
    pub format_version: u8,
    pub declared_count: u32,
    pub entries: Vec<ParsedResourceEntry>,
    pub best_effort: bool,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedModule {
    pub name: String,
    pub is_package: bool,
    pub source: Option<Vec<u8>>,
    pub bytecode: Option<Vec<u8>>,
    pub bytecode_opt1: Option<Vec<u8>>,
    pub bytecode_opt2: Option<Vec<u8>>,
    pub extension_len: Option<usize>,
    pub fs_relative_source: bool,
    pub fs_relative_bytecode: bool,
    pub fs_relative_extension: bool,
    pub fs_relative_source_path: Option<String>,
    pub fs_relative_bytecode_path: Option<String>,
    pub fs_relative_bytecode_opt1_path: Option<String>,
    pub fs_relative_bytecode_opt2_path: Option<String>,
    pub fs_relative_extension_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModuleExtractionError {
    #[error("v3 packed-resources module index failed bounds/consistency checks")]
    MalformedV3Resources,
}

#[derive(Debug, Clone, Copy)]
struct Header {
    blob_section_count: u8,
    blob_index_length: usize,
    resources_count: u32,
    resources_index_length: usize,
}

#[derive(Debug, Clone, Copy)]
struct BlobSection {
    resource_field: u8,
    raw_payload_length: usize,
    null_padding: bool,
}

#[derive(Debug, Clone, Copy)]
struct SectionCursor {
    offset: usize,
    null_padding: bool,
}

fn read_header(region: &[u8]) -> Option<Header> {
    let trailer_end: usize = MAGIC_LEN.checked_add(HEADER_TRAILER_LEN)?;
    let trailer: &[u8] = region.get(MAGIC_LEN..trailer_end)?;
    let blob_section_count: u8 = trailer[0];
    let blob_index_length: usize = usize::try_from(u32::from_le_bytes([
        trailer[1], trailer[2], trailer[3], trailer[4],
    ]))
    .ok()?;
    let resources_count: u32 = u32::from_le_bytes([trailer[5], trailer[6], trailer[7], trailer[8]]);
    let resources_index_length: usize = usize::try_from(u32::from_le_bytes([
        trailer[9],
        trailer[10],
        trailer[11],
        trailer[12],
    ]))
    .ok()?;
    Some(Header {
        blob_section_count,
        blob_index_length,
        resources_count,
        resources_index_length,
    })
}

fn parse_blob_index(region: &[u8], start: usize, index_len: usize) -> Option<Vec<BlobSection>> {
    let index_end: usize = start.checked_add(index_len)?;
    let index: &[u8] = region.get(start..index_end)?;
    let mut sections: Vec<BlobSection> = Vec::new();
    let mut cursor: usize = 0;
    let mut field: Option<u8> = None;
    let mut payload_len: Option<usize> = None;
    let mut null_padding: bool = false;
    loop {
        let opcode: u8 = *index.get(cursor)?;
        cursor += 1;
        match opcode {
            BLOB_END_OF_INDEX => break,
            BLOB_START_OF_ENTRY => {
                field = None;
                payload_len = None;
                null_padding = false;
            }
            BLOB_END_OF_ENTRY => {
                let resource_field: u8 = field?;
                let raw_payload_length: usize = payload_len?;
                sections.push(BlobSection {
                    resource_field,
                    raw_payload_length,
                    null_padding,
                });
                field = None;
                payload_len = None;
                null_padding = false;
            }
            BLOB_RESOURCE_FIELD_TYPE => {
                field = Some(*index.get(cursor)?);
                cursor += 1;
            }
            BLOB_RAW_PAYLOAD_LENGTH => {
                let end: usize = cursor.checked_add(8)?;
                let raw: &[u8] = index.get(cursor..end)?;
                let value: u64 = u64::from_le_bytes(raw.try_into().ok()?);
                payload_len = Some(usize::try_from(value).ok()?);
                cursor = end;
            }
            BLOB_INTERIOR_PADDING => {
                let pad: u8 = *index.get(cursor)?;
                cursor += 1;
                null_padding = match pad {
                    PADDING_NONE => false,
                    PADDING_NULL => true,
                    _ => return None,
                };
            }
            _ => return None,
        }
    }
    Some(sections)
}

fn build_section_cursors(
    header: &Header,
    sections: &[BlobSection],
) -> Option<[Option<SectionCursor>; RESOURCE_FIELD_SLOTS]> {
    if sections.len() != usize::from(header.blob_section_count) {
        return None;
    }
    let blobs_start: usize = MAGIC_LEN
        .checked_add(HEADER_TRAILER_LEN)?
        .checked_add(header.blob_index_length)?
        .checked_add(header.resources_index_length)?;
    let mut cursors: [Option<SectionCursor>; RESOURCE_FIELD_SLOTS] = [None; RESOURCE_FIELD_SLOTS];
    let mut running: usize = 0;
    for section in sections {
        let offset: usize = blobs_start.checked_add(running)?;
        let field: usize = usize::from(section.resource_field);
        let slot: &mut Option<SectionCursor> = cursors.get_mut(field)?;
        *slot = Some(SectionCursor {
            offset,
            null_padding: section.null_padding,
        });
        running = running.checked_add(section.raw_payload_length)?;
    }
    Some(cursors)
}

fn take_blob<'a>(
    region: &'a [u8],
    cursors: &mut [Option<SectionCursor>; RESOURCE_FIELD_SLOTS],
    field: u8,
    length: usize,
) -> Option<(usize, &'a [u8])> {
    let cursor: &mut SectionCursor = cursors.get_mut(usize::from(field))?.as_mut()?;
    let start: usize = cursor.offset;
    let end: usize = start.checked_add(length)?;
    let slice: &[u8] = region.get(start..end)?;
    let advance: usize = if cursor.null_padding {
        length.checked_add(1)?
    } else {
        length
    };
    cursor.offset = start.checked_add(advance)?;
    Some((start, slice))
}

#[must_use]
pub fn parse_packed_resources(blob: &[u8]) -> Option<PackedResourcesParse> {
    let magic_pos: usize = find_packed_magic(blob)?;
    let region: &[u8] = &blob[magic_pos..];
    let format_version: u8 = *region.get(MAGIC_PREFIX.len())?;
    if let Some(parse) = parse_structured_region(region) {
        return Some(parse);
    }
    let diagnostics: Vec<String> = vec![
        "structured parse failed bounds/consistency checks; falling back to heuristic walk"
            .to_owned(),
    ];
    Some(heuristic_walk(region, format_version, 0, diagnostics))
}

fn parse_structured_region(region: &[u8]) -> Option<PackedResourcesParse> {
    let header: Header = read_header(region)?;
    let format_version: u8 = *region.get(MAGIC_PREFIX.len())?;
    let sections: Vec<BlobSection> = parse_blob_index(
        region,
        MAGIC_LEN + HEADER_TRAILER_LEN,
        header.blob_index_length,
    )?;
    let mut cursors: [Option<SectionCursor>; RESOURCE_FIELD_SLOTS] =
        build_section_cursors(&header, &sections)?;
    let resources_index_start: usize = MAGIC_LEN
        .checked_add(HEADER_TRAILER_LEN)?
        .checked_add(header.blob_index_length)?;
    let resources_index_end: usize =
        resources_index_start.checked_add(header.resources_index_length)?;
    let resources_index: &[u8] = region.get(resources_index_start..resources_index_end)?;

    let mut entries: Vec<ParsedResourceEntry> = Vec::new();
    let mut read_count: u32 = 0;
    let mut cursor: usize = 0;
    let mut current: Option<RawEntry> = None;

    loop {
        let opcode: u8 = *resources_index.get(cursor)?;
        cursor += 1;
        match opcode {
            RES_END_OF_INDEX => break,
            RES_START_OF_ENTRY => {
                read_count = read_count.checked_add(1)?;
                current = Some(RawEntry::default());
            }
            RES_END_OF_ENTRY => {
                let entry: RawEntry = current.take()?;
                let name: String = entry.name.clone()?;
                let tier: ResourceTier = tier_for_entry(&entry, &name);
                let (content_offset, content_len): (usize, usize) =
                    primary_payload(&entry).unwrap_or((0, 0));
                entries.push(ParsedResourceEntry {
                    tier,
                    name,
                    content_offset,
                    content_len,
                });
            }
            RES_NAME => {
                let length: usize = read_u16(resources_index, &mut cursor)?;
                let (_, slice): (usize, &[u8]) = take_blob(region, &mut cursors, RES_NAME, length)?;
                let text: &str = std::str::from_utf8(slice).ok()?;
                let entry: &mut RawEntry = current.as_mut()?;
                entry.name = Some(text.to_owned());
            }
            RES_IN_MEMORY_SOURCE => {
                let length: usize = read_u32(resources_index, &mut cursor)?;
                let (offset, _): (usize, &[u8]) =
                    take_blob(region, &mut cursors, RES_IN_MEMORY_SOURCE, length)?;
                current.as_mut()?.source = Some((offset, length));
            }
            RES_IN_MEMORY_BYTECODE => {
                let length: usize = read_u32(resources_index, &mut cursor)?;
                let (offset, _): (usize, &[u8]) =
                    take_blob(region, &mut cursors, RES_IN_MEMORY_BYTECODE, length)?;
                current.as_mut()?.bytecode = Some((offset, length));
            }
            RES_IN_MEMORY_BYTECODE_OPT1 => {
                let length: usize = read_u32(resources_index, &mut cursor)?;
                let (offset, _): (usize, &[u8]) =
                    take_blob(region, &mut cursors, RES_IN_MEMORY_BYTECODE_OPT1, length)?;
                current.as_mut()?.bytecode_opt1 = Some((offset, length));
            }
            RES_IN_MEMORY_BYTECODE_OPT2 => {
                let length: usize = read_u32(resources_index, &mut cursor)?;
                let (offset, _): (usize, &[u8]) =
                    take_blob(region, &mut cursors, RES_IN_MEMORY_BYTECODE_OPT2, length)?;
                current.as_mut()?.bytecode_opt2 = Some((offset, length));
            }
            RES_IN_MEMORY_EXTENSION_MODULE => {
                let length: usize = read_u32(resources_index, &mut cursor)?;
                let (offset, _): (usize, &[u8]) =
                    take_blob(region, &mut cursors, RES_IN_MEMORY_EXTENSION_MODULE, length)?;
                current.as_mut()?.extension = Some((offset, length));
            }
            RES_IN_MEMORY_RESOURCES_DATA | RES_IN_MEMORY_DISTRIBUTION_RESOURCE => {
                skip_named_map_u64(region, resources_index, &mut cursor, &mut cursors, opcode)?;
            }
            RES_IN_MEMORY_SHARED_LIBRARY => {
                let length: usize = read_u64(resources_index, &mut cursor)?;
                take_blob(region, &mut cursors, RES_IN_MEMORY_SHARED_LIBRARY, length)?;
            }
            RES_SHARED_LIBRARY_DEPENDENCY_NAMES => {
                skip_name_list(region, resources_index, &mut cursor, &mut cursors, opcode)?;
            }
            RES_RELATIVE_FS_MODULE_SOURCE
            | RES_RELATIVE_FS_MODULE_BYTECODE
            | RES_RELATIVE_FS_MODULE_BYTECODE_OPT1
            | RES_RELATIVE_FS_MODULE_BYTECODE_OPT2
            | RES_RELATIVE_FS_EXTENSION_MODULE => {
                let length: usize = read_u32(resources_index, &mut cursor)?;
                take_blob(region, &mut cursors, opcode, length)?;
            }
            RES_RELATIVE_FS_PACKAGE_RESOURCES | RES_RELATIVE_FS_DISTRIBUTION_RESOURCE => {
                skip_named_map_u32(region, resources_index, &mut cursor, &mut cursors, opcode)?;
            }
            RES_IS_PYTHON_PACKAGE
            | RES_IS_PYTHON_NAMESPACE_PACKAGE
            | RES_IS_PYTHON_MODULE
            | RES_IS_PYTHON_BUILTIN_EXTENSION_MODULE
            | RES_IS_PYTHON_FROZEN_MODULE
            | RES_IS_PYTHON_EXTENSION_MODULE
            | RES_IS_SHARED_LIBRARY
            | RES_IS_UTF8_FILENAME_DATA
            | RES_FILE_EXECUTABLE => {
                current.as_mut()?;
            }
            RES_FILE_DATA_EMBEDDED => {
                let length: usize = read_u64(resources_index, &mut cursor)?;
                take_blob(region, &mut cursors, RES_FILE_DATA_EMBEDDED, length)?;
            }
            RES_FILE_DATA_UTF8_RELATIVE_PATH => {
                let length: usize = read_u32(resources_index, &mut cursor)?;
                take_blob(
                    region,
                    &mut cursors,
                    RES_FILE_DATA_UTF8_RELATIVE_PATH,
                    length,
                )?;
            }
            _ => return None,
        }
    }

    if read_count != header.resources_count {
        return None;
    }

    let diagnostics: Vec<String> = vec![format!(
        "pyembed v{version} packed-resources index parsed exactly: {sections} blob sections, {count} resources, {bytes}-byte blob region",
        version = format_version,
        sections = header.blob_section_count,
        count = header.resources_count,
        bytes = region.len()
    )];

    Some(PackedResourcesParse {
        format_version,
        declared_count: header.resources_count,
        entries,
        best_effort: false,
        diagnostics,
    })
}

#[derive(Debug, Default, Clone)]
struct RawEntry {
    name: Option<String>,
    source: Option<(usize, usize)>,
    bytecode: Option<(usize, usize)>,
    bytecode_opt1: Option<(usize, usize)>,
    bytecode_opt2: Option<(usize, usize)>,
    extension: Option<(usize, usize)>,
}

fn tier_for_entry(entry: &RawEntry, name: &str) -> ResourceTier {
    if entry.bytecode.is_some() {
        return ResourceTier::Bytecode;
    }
    if entry.bytecode_opt1.is_some() {
        return ResourceTier::BytecodeOpt1;
    }
    if entry.bytecode_opt2.is_some() {
        return ResourceTier::BytecodeOpt2;
    }
    if entry.source.is_some() {
        return ResourceTier::Source;
    }
    if entry.extension.is_some() {
        return ResourceTier::Extension;
    }
    tier_for_name(name)
}

fn primary_payload(entry: &RawEntry) -> Option<(usize, usize)> {
    entry
        .bytecode
        .or(entry.bytecode_opt1)
        .or(entry.bytecode_opt2)
        .or(entry.source)
        .or(entry.extension)
}

fn skip_named_map_u64(
    region: &[u8],
    index: &[u8],
    cursor: &mut usize,
    cursors: &mut [Option<SectionCursor>; RESOURCE_FIELD_SLOTS],
    field: u8,
) -> Option<()> {
    let count: usize = read_u32(index, cursor)?;
    for _ in 0..count {
        let name_len: usize = read_u16(index, cursor)?;
        take_blob(region, cursors, field, name_len)?;
        let value_len: usize = read_u64(index, cursor)?;
        take_blob(region, cursors, field, value_len)?;
    }
    Some(())
}

fn skip_named_map_u32(
    region: &[u8],
    index: &[u8],
    cursor: &mut usize,
    cursors: &mut [Option<SectionCursor>; RESOURCE_FIELD_SLOTS],
    field: u8,
) -> Option<()> {
    let count: usize = read_u32(index, cursor)?;
    for _ in 0..count {
        let name_len: usize = read_u16(index, cursor)?;
        take_blob(region, cursors, field, name_len)?;
        let path_len: usize = read_u32(index, cursor)?;
        take_blob(region, cursors, field, path_len)?;
    }
    Some(())
}

fn skip_name_list(
    region: &[u8],
    index: &[u8],
    cursor: &mut usize,
    cursors: &mut [Option<SectionCursor>; RESOURCE_FIELD_SLOTS],
    field: u8,
) -> Option<()> {
    let count: usize = read_u16(index, cursor)?;
    for _ in 0..count {
        let name_len: usize = read_u16(index, cursor)?;
        take_blob(region, cursors, field, name_len)?;
    }
    Some(())
}

pub fn extract_modules(blob: &[u8]) -> Result<Vec<ExtractedModule>, ModuleExtractionError> {
    let Some(magic_pos): Option<usize> = find_packed_magic(blob) else {
        return Ok(Vec::new());
    };
    let region: &[u8] = &blob[magic_pos..];
    extract_modules_structured(region).ok_or(ModuleExtractionError::MalformedV3Resources)
}

fn extract_modules_structured(region: &[u8]) -> Option<Vec<ExtractedModule>> {
    let header: Header = read_header(region)?;
    let sections: Vec<BlobSection> = parse_blob_index(
        region,
        MAGIC_LEN + HEADER_TRAILER_LEN,
        header.blob_index_length,
    )?;
    let mut cursors: [Option<SectionCursor>; RESOURCE_FIELD_SLOTS] =
        build_section_cursors(&header, &sections)?;
    let resources_index_start: usize = MAGIC_LEN
        .checked_add(HEADER_TRAILER_LEN)?
        .checked_add(header.blob_index_length)?;
    let resources_index_end: usize =
        resources_index_start.checked_add(header.resources_index_length)?;
    let resources_index: &[u8] = region.get(resources_index_start..resources_index_end)?;

    let mut modules: Vec<ExtractedModule> = Vec::new();
    let mut current: Option<RawModule> = None;
    let mut cursor: usize = 0;
    loop {
        let opcode: u8 = *resources_index.get(cursor)?;
        cursor += 1;
        match opcode {
            RES_END_OF_INDEX => break,
            RES_START_OF_ENTRY => current = Some(RawModule::default()),
            RES_END_OF_ENTRY => {
                let m: RawModule = current.take()?;
                let name: String = m.name?;
                modules.push(ExtractedModule {
                    name,
                    is_package: m.is_package,
                    source: m.source,
                    bytecode: m.bytecode,
                    bytecode_opt1: m.bytecode_opt1,
                    bytecode_opt2: m.bytecode_opt2,
                    extension_len: m.extension_len,
                    fs_relative_source: m.fs_relative_source,
                    fs_relative_bytecode: m.fs_relative_bytecode,
                    fs_relative_extension: m.fs_relative_extension,
                    fs_relative_source_path: m.fs_relative_source_path,
                    fs_relative_bytecode_path: m.fs_relative_bytecode_path,
                    fs_relative_bytecode_opt1_path: m.fs_relative_bytecode_opt1_path,
                    fs_relative_bytecode_opt2_path: m.fs_relative_bytecode_opt2_path,
                    fs_relative_extension_path: m.fs_relative_extension_path,
                });
            }
            RES_NAME => {
                let length: usize = read_u16(resources_index, &mut cursor)?;
                let (_, slice): (usize, &[u8]) = take_blob(region, &mut cursors, RES_NAME, length)?;
                let text: &str = std::str::from_utf8(slice).ok()?;
                current.as_mut()?.name = Some(text.to_owned());
            }
            RES_IS_PYTHON_PACKAGE => {
                current.as_mut()?.is_package = true;
            }
            RES_IN_MEMORY_SOURCE => {
                let length: usize = read_u32(resources_index, &mut cursor)?;
                let (_, slice): (usize, &[u8]) =
                    take_blob(region, &mut cursors, RES_IN_MEMORY_SOURCE, length)?;
                current.as_mut()?.source = Some(slice.to_vec());
            }
            RES_IN_MEMORY_BYTECODE => {
                let length: usize = read_u32(resources_index, &mut cursor)?;
                let (_, slice): (usize, &[u8]) =
                    take_blob(region, &mut cursors, RES_IN_MEMORY_BYTECODE, length)?;
                current.as_mut()?.bytecode = Some(slice.to_vec());
            }
            RES_IN_MEMORY_BYTECODE_OPT1 => {
                let length: usize = read_u32(resources_index, &mut cursor)?;
                let (_, slice): (usize, &[u8]) =
                    take_blob(region, &mut cursors, RES_IN_MEMORY_BYTECODE_OPT1, length)?;
                current.as_mut()?.bytecode_opt1 = Some(slice.to_vec());
            }
            RES_IN_MEMORY_BYTECODE_OPT2 => {
                let length: usize = read_u32(resources_index, &mut cursor)?;
                let (_, slice): (usize, &[u8]) =
                    take_blob(region, &mut cursors, RES_IN_MEMORY_BYTECODE_OPT2, length)?;
                current.as_mut()?.bytecode_opt2 = Some(slice.to_vec());
            }
            RES_IN_MEMORY_EXTENSION_MODULE => {
                let length: usize = read_u32(resources_index, &mut cursor)?;
                take_blob(region, &mut cursors, RES_IN_MEMORY_EXTENSION_MODULE, length)?;
                current.as_mut()?.extension_len = Some(length);
            }
            RES_IN_MEMORY_RESOURCES_DATA | RES_IN_MEMORY_DISTRIBUTION_RESOURCE => {
                skip_named_map_u64(region, resources_index, &mut cursor, &mut cursors, opcode)?;
            }
            RES_IN_MEMORY_SHARED_LIBRARY => {
                let length: usize = read_u64(resources_index, &mut cursor)?;
                take_blob(region, &mut cursors, RES_IN_MEMORY_SHARED_LIBRARY, length)?;
            }
            RES_SHARED_LIBRARY_DEPENDENCY_NAMES => {
                skip_name_list(region, resources_index, &mut cursor, &mut cursors, opcode)?;
            }
            RES_RELATIVE_FS_MODULE_SOURCE => {
                let length: usize = read_u32(resources_index, &mut cursor)?;
                let (_, slice): (usize, &[u8]) = take_blob(region, &mut cursors, opcode, length)?;
                let module: &mut RawModule = current.as_mut()?;
                module.fs_relative_source = true;
                if let Ok(path) = std::str::from_utf8(slice) {
                    module.fs_relative_source_path = Some(path.to_owned());
                }
            }
            RES_RELATIVE_FS_MODULE_BYTECODE
            | RES_RELATIVE_FS_MODULE_BYTECODE_OPT1
            | RES_RELATIVE_FS_MODULE_BYTECODE_OPT2 => {
                let length: usize = read_u32(resources_index, &mut cursor)?;
                let (_, slice): (usize, &[u8]) = take_blob(region, &mut cursors, opcode, length)?;
                let module: &mut RawModule = current.as_mut()?;
                module.fs_relative_bytecode = true;
                if let Ok(path) = std::str::from_utf8(slice) {
                    let owned: String = path.to_owned();
                    match opcode {
                        RES_RELATIVE_FS_MODULE_BYTECODE => {
                            module.fs_relative_bytecode_path = Some(owned);
                        }
                        RES_RELATIVE_FS_MODULE_BYTECODE_OPT1 => {
                            module.fs_relative_bytecode_opt1_path = Some(owned);
                        }
                        _ => module.fs_relative_bytecode_opt2_path = Some(owned),
                    }
                }
            }
            RES_RELATIVE_FS_EXTENSION_MODULE => {
                let length: usize = read_u32(resources_index, &mut cursor)?;
                let (_, slice): (usize, &[u8]) = take_blob(region, &mut cursors, opcode, length)?;
                let module: &mut RawModule = current.as_mut()?;
                module.fs_relative_extension = true;
                if let Ok(path) = std::str::from_utf8(slice) {
                    module.fs_relative_extension_path = Some(path.to_owned());
                }
            }
            RES_RELATIVE_FS_PACKAGE_RESOURCES | RES_RELATIVE_FS_DISTRIBUTION_RESOURCE => {
                skip_named_map_u32(region, resources_index, &mut cursor, &mut cursors, opcode)?;
            }
            RES_IS_PYTHON_NAMESPACE_PACKAGE
            | RES_IS_PYTHON_MODULE
            | RES_IS_PYTHON_BUILTIN_EXTENSION_MODULE
            | RES_IS_PYTHON_FROZEN_MODULE
            | RES_IS_PYTHON_EXTENSION_MODULE
            | RES_IS_SHARED_LIBRARY
            | RES_IS_UTF8_FILENAME_DATA
            | RES_FILE_EXECUTABLE => {
                current.as_mut()?;
            }
            RES_FILE_DATA_EMBEDDED => {
                let length: usize = read_u64(resources_index, &mut cursor)?;
                take_blob(region, &mut cursors, RES_FILE_DATA_EMBEDDED, length)?;
            }
            RES_FILE_DATA_UTF8_RELATIVE_PATH => {
                let length: usize = read_u32(resources_index, &mut cursor)?;
                take_blob(
                    region,
                    &mut cursors,
                    RES_FILE_DATA_UTF8_RELATIVE_PATH,
                    length,
                )?;
            }
            _ => return None,
        }
    }
    Some(modules)
}

#[derive(Debug, Default, Clone)]
struct RawModule {
    name: Option<String>,
    is_package: bool,
    source: Option<Vec<u8>>,
    bytecode: Option<Vec<u8>>,
    bytecode_opt1: Option<Vec<u8>>,
    bytecode_opt2: Option<Vec<u8>>,
    extension_len: Option<usize>,
    fs_relative_source: bool,
    fs_relative_bytecode: bool,
    fs_relative_extension: bool,
    fs_relative_source_path: Option<String>,
    fs_relative_bytecode_path: Option<String>,
    fs_relative_bytecode_opt1_path: Option<String>,
    fs_relative_bytecode_opt2_path: Option<String>,
    fs_relative_extension_path: Option<String>,
}

fn read_u16(buf: &[u8], cursor: &mut usize) -> Option<usize> {
    let end: usize = cursor.checked_add(2)?;
    let raw: &[u8] = buf.get(*cursor..end)?;
    *cursor = end;
    Some(usize::from(u16::from_le_bytes(raw.try_into().ok()?)))
}

fn read_u32(buf: &[u8], cursor: &mut usize) -> Option<usize> {
    let end: usize = cursor.checked_add(4)?;
    let raw: &[u8] = buf.get(*cursor..end)?;
    *cursor = end;
    usize::try_from(u32::from_le_bytes(raw.try_into().ok()?)).ok()
}

fn read_u64(buf: &[u8], cursor: &mut usize) -> Option<usize> {
    let end: usize = cursor.checked_add(8)?;
    let raw: &[u8] = buf.get(*cursor..end)?;
    *cursor = end;
    usize::try_from(u64::from_le_bytes(raw.try_into().ok()?)).ok()
}

fn tier_for_name(name: &str) -> ResourceTier {
    let ext: Option<String> = std::path::Path::new(name)
        .extension()
        .and_then(|e: &std::ffi::OsStr| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("py") => ResourceTier::Source,
        Some("pyc") => ResourceTier::Bytecode,
        Some("pyd" | "so") => ResourceTier::Extension,
        _ if name.contains("__pycache__") => ResourceTier::Bytecode,
        _ => ResourceTier::Resource,
    }
}

fn heuristic_walk(
    blob: &[u8],
    format_version: u8,
    declared_count: u32,
    mut diagnostics: Vec<String>,
) -> PackedResourcesParse {
    let mut entries: Vec<ParsedResourceEntry> = Vec::new();
    let needles: [(&[u8], ResourceTier); 4] = [
        (b"__pycache__/", ResourceTier::Bytecode),
        (b".pyc", ResourceTier::Bytecode),
        (b".py\0", ResourceTier::Source),
        (b".pyd", ResourceTier::Extension),
    ];
    for (needle, tier) in needles {
        let mut start: usize = 0;
        while let Some(pos) = find_from(blob, needle, start) {
            let name_start: usize = scan_name_start(blob, pos);
            let name_end: usize = pos + needle.len();
            let raw_name: &[u8] = &blob[name_start..name_end];
            if let Ok(text) = std::str::from_utf8(raw_name) {
                entries.push(ParsedResourceEntry {
                    tier,
                    name: text.trim_end_matches('\0').to_owned(),
                    content_offset: name_end,
                    content_len: 0,
                });
            }
            start = pos + needle.len();
        }
    }

    if find(blob, b"PK\x05\x06").is_some() || find(blob, b"PK\x01\x02").is_some() {
        diagnostics.push(
            "blob contains zip central-directory markers; treat content as embedded zip archive"
                .to_owned(),
        );
    }

    diagnostics.push(format!(
        "heuristic walk surfaced {n} candidate names (best-effort, format not authoritative)",
        n = entries.len()
    ));
    PackedResourcesParse {
        format_version,
        declared_count,
        entries,
        best_effort: true,
        diagnostics,
    }
}

fn scan_name_start(blob: &[u8], anchor: usize) -> usize {
    let mut i: usize = anchor;
    while i > 0 {
        let prev: u8 = blob[i - 1];
        let printable: bool =
            prev.is_ascii_alphanumeric() || matches!(prev, b'_' | b'-' | b'.' | b'/' | b'\\');
        if !printable {
            break;
        }
        i -= 1;
    }
    i
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    find_from(haystack, needle, 0)
}

fn find_from(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() || haystack.len() - start < needle.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + start)
}

fn packed_magic(version: u8) -> [u8; MAGIC_LEN] {
    let mut magic: [u8; MAGIC_LEN] = [0u8; MAGIC_LEN];
    magic[..MAGIC_PREFIX.len()].copy_from_slice(MAGIC_PREFIX);
    magic[MAGIC_PREFIX.len()] = version;
    magic
}

fn find_packed_magic(bytes: &[u8]) -> Option<usize> {
    let mut start: usize = 0;
    while let Some(pos) = find_from(bytes, MAGIC_PREFIX, start) {
        if let Some(&version) = bytes.get(pos + MAGIC_PREFIX.len())
            && version <= MAX_STRUCTURED_VERSION
        {
            return Some(pos);
        }
        start = pos + MAGIC_PREFIX.len();
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn scan_picks_up_pyembed_runtime() {
        let mut buf: Vec<u8> = vec![0u8; 64];
        buf.extend_from_slice(b"pyembed");
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(b"python-stdlib");
        let markers: Vec<String> = scan(&buf);
        assert!(is_present(&markers), "markers: {markers:?}");
    }

    #[test]
    fn scan_rejects_unrelated_strings() {
        let buf: Vec<u8> = b"random bytes with no markers at all".to_vec();
        let markers: Vec<String> = scan(&buf);
        assert!(!is_present(&markers));
    }

    #[test]
    fn scan_requires_runtime_marker_not_just_aux() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"python-stdlib");
        buf.extend_from_slice(b"PythonInterpreterConfig");
        let markers: Vec<String> = scan(&buf);
        assert!(!is_present(&markers));
    }

    #[test]
    fn version_inference_python_312() {
        let mut buf: Vec<u8> = vec![0u8; 32];
        buf.extend_from_slice(b"python312.dll\0");
        let (maj, min, hint): (Option<u8>, Option<u8>, Option<String>) = infer_python_version(&buf);
        assert_eq!(maj, Some(3));
        assert_eq!(min, Some(12));
        assert_eq!(hint.as_deref(), Some("python312.dll"));
    }

    #[test]
    fn version_inference_libpython_311() {
        let mut buf: Vec<u8> = vec![0u8; 32];
        buf.extend_from_slice(b"libpython3.11.so.1\0");
        let (maj, min, _): (Option<u8>, Option<u8>, Option<String>) = infer_python_version(&buf);
        assert_eq!(maj, Some(3));
        assert_eq!(min, Some(11));
    }

    #[test]
    fn version_inference_returns_none_without_marker() {
        let (maj, _, _): (Option<u8>, Option<u8>, Option<String>) =
            infer_python_version(b"nothing python here");
        assert_eq!(maj, None);
    }

    #[test]
    fn blob_extraction_anchors_on_real_v3_magic() {
        let blob: Vec<u8> = build_real_v3_blob(&[V3Module {
            name: "m",
            is_package: false,
            source: None,
            bytecode: Some(b"BC"),
        }]);
        let mut buf: Vec<u8> = vec![0xAB; 128];
        buf.extend_from_slice(&blob);
        buf.extend_from_slice(&[0xCD; 64]);
        let slice: &[u8] = extract_resources_blob(&buf).expect("blob present");
        assert!(slice.starts_with(b"pyembed\x03"));
        assert_eq!(slice.len(), blob.len(), "must trim to measured blob length");
    }

    #[test]
    fn blob_extraction_falls_back_to_legacy_string_anchor() {
        let mut buf: Vec<u8> = vec![0xAB; 64];
        buf.extend_from_slice(b"pyembed-resources-0");
        buf.extend_from_slice(&[0xCD; 32]);
        let slice: &[u8] = extract_resources_blob(&buf).expect("legacy blob present");
        assert!(slice.starts_with(b"pyembed-resources-0"));
    }

    #[test]
    fn blob_extraction_returns_none_when_absent() {
        assert!(extract_resources_blob(b"plain bytes").is_none());
    }

    struct V3Module<'a> {
        name: &'a str,
        is_package: bool,
        source: Option<&'a [u8]>,
        bytecode: Option<&'a [u8]>,
    }

    fn build_real_v3_blob(modules: &[V3Module<'_>]) -> Vec<u8> {
        let mut name_section: Vec<u8> = Vec::new();
        let mut source_section: Vec<u8> = Vec::new();
        let mut bytecode_section: Vec<u8> = Vec::new();
        for m in modules {
            name_section.extend_from_slice(m.name.as_bytes());
            if let Some(s) = m.source {
                source_section.extend_from_slice(s);
            }
            if let Some(b) = m.bytecode {
                bytecode_section.extend_from_slice(b);
            }
        }

        let mut blob_index: Vec<u8> = Vec::new();
        let mut blob_section_count: u8 = 0;
        let push_section = |index: &mut Vec<u8>, count: &mut u8, field: u8, len: usize| {
            index.push(BLOB_START_OF_ENTRY);
            index.push(BLOB_RESOURCE_FIELD_TYPE);
            index.push(field);
            index.push(BLOB_RAW_PAYLOAD_LENGTH);
            index.extend_from_slice(&(len as u64).to_le_bytes());
            index.push(BLOB_INTERIOR_PADDING);
            index.push(PADDING_NONE);
            index.push(BLOB_END_OF_ENTRY);
            *count += 1;
        };
        push_section(
            &mut blob_index,
            &mut blob_section_count,
            RES_NAME,
            name_section.len(),
        );
        if !source_section.is_empty() {
            push_section(
                &mut blob_index,
                &mut blob_section_count,
                RES_IN_MEMORY_SOURCE,
                source_section.len(),
            );
        }
        if !bytecode_section.is_empty() {
            push_section(
                &mut blob_index,
                &mut blob_section_count,
                RES_IN_MEMORY_BYTECODE,
                bytecode_section.len(),
            );
        }
        blob_index.push(BLOB_END_OF_INDEX);

        let mut resources_index: Vec<u8> = Vec::new();
        for m in modules {
            resources_index.push(RES_START_OF_ENTRY);
            resources_index.push(RES_NAME);
            resources_index.extend_from_slice(&(m.name.len() as u16).to_le_bytes());
            if m.is_package {
                resources_index.push(RES_IS_PYTHON_PACKAGE);
            }
            resources_index.push(RES_IS_PYTHON_MODULE);
            if let Some(s) = m.source {
                resources_index.push(RES_IN_MEMORY_SOURCE);
                resources_index.extend_from_slice(&(s.len() as u32).to_le_bytes());
            }
            if let Some(b) = m.bytecode {
                resources_index.push(RES_IN_MEMORY_BYTECODE);
                resources_index.extend_from_slice(&(b.len() as u32).to_le_bytes());
            }
            resources_index.push(RES_END_OF_ENTRY);
        }
        resources_index.push(RES_END_OF_INDEX);

        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(BLOB_MAGIC_V3);
        out.push(blob_section_count);
        out.extend_from_slice(&(blob_index.len() as u32).to_le_bytes());
        out.extend_from_slice(&(modules.len() as u32).to_le_bytes());
        out.extend_from_slice(&(resources_index.len() as u32).to_le_bytes());
        out.extend_from_slice(&blob_index);
        out.extend_from_slice(&resources_index);
        out.extend_from_slice(&name_section);
        out.extend_from_slice(&source_section);
        out.extend_from_slice(&bytecode_section);
        out
    }

    #[test]
    fn parse_v3_index_recovers_names_and_tiers_from_blob_sections() {
        let blob: Vec<u8> = build_real_v3_blob(&[
            V3Module {
                name: "pkg",
                is_package: true,
                source: None,
                bytecode: Some(b"PKGBYTECODE"),
            },
            V3Module {
                name: "pkg.mod",
                is_package: false,
                source: Some(b"x = 1\n"),
                bytecode: Some(b"MODBYTECODE"),
            },
        ]);
        let parsed: PackedResourcesParse = parse_packed_resources(&blob).expect("parse");
        assert_eq!(parsed.format_version, 0x03);
        assert_eq!(parsed.declared_count, 2);
        assert_eq!(parsed.entries.len(), 2);
        assert!(!parsed.best_effort, "diagnostics: {:?}", parsed.diagnostics);
        assert_eq!(parsed.entries[0].name, "pkg");
        assert_eq!(parsed.entries[0].tier, ResourceTier::Bytecode);
        assert_eq!(parsed.entries[1].name, "pkg.mod");
        assert_eq!(parsed.entries[1].tier, ResourceTier::Bytecode);
    }

    #[test]
    fn extract_modules_recovers_exact_payload_bytes() {
        let bytecode_a: &[u8] = b"\xde\xad\xbe\xef bytecode body for module a";
        let bytecode_b: &[u8] = b"second module bytecode \x00\x01\x02 body";
        let source_b: &[u8] = b"def f():\n    return 42\n";
        let blob: Vec<u8> = build_real_v3_blob(&[
            V3Module {
                name: "alpha",
                is_package: false,
                source: None,
                bytecode: Some(bytecode_a),
            },
            V3Module {
                name: "beta",
                is_package: true,
                source: Some(source_b),
                bytecode: Some(bytecode_b),
            },
        ]);
        let modules: Vec<ExtractedModule> = extract_modules(&blob).expect("extract modules");
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].name, "alpha");
        assert_eq!(modules[0].bytecode.as_deref(), Some(bytecode_a));
        assert!(modules[0].source.is_none());
        assert_eq!(modules[1].name, "beta");
        assert!(modules[1].is_package);
        assert_eq!(modules[1].source.as_deref(), Some(source_b));
        assert_eq!(modules[1].bytecode.as_deref(), Some(bytecode_b));
    }

    #[test]
    fn extract_modules_handles_null_padding_between_blobs() {
        let blob: Vec<u8> = build_null_padded_v3_blob(&[("first", b"AAAA"), ("second", b"BBBBBB")]);
        let modules: Vec<ExtractedModule> = extract_modules(&blob).expect("extract modules");
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].name, "first");
        assert_eq!(modules[0].bytecode.as_deref(), Some(&b"AAAA"[..]));
        assert_eq!(modules[1].name, "second");
        assert_eq!(modules[1].bytecode.as_deref(), Some(&b"BBBBBB"[..]));
    }

    fn build_null_padded_v3_blob(modules: &[(&str, &[u8])]) -> Vec<u8> {
        let mut name_section: Vec<u8> = Vec::new();
        let mut bytecode_section: Vec<u8> = Vec::new();
        for (name, bc) in modules {
            name_section.extend_from_slice(name.as_bytes());
            name_section.push(0x00);
            bytecode_section.extend_from_slice(bc);
            bytecode_section.push(0x00);
        }

        let mut blob_index: Vec<u8> = Vec::new();
        let mut count: u8 = 0;
        let push_section = |index: &mut Vec<u8>, c: &mut u8, field: u8, len: usize| {
            index.push(BLOB_START_OF_ENTRY);
            index.push(BLOB_RESOURCE_FIELD_TYPE);
            index.push(field);
            index.push(BLOB_RAW_PAYLOAD_LENGTH);
            index.extend_from_slice(&(len as u64).to_le_bytes());
            index.push(BLOB_INTERIOR_PADDING);
            index.push(PADDING_NULL);
            index.push(BLOB_END_OF_ENTRY);
            *c += 1;
        };
        push_section(&mut blob_index, &mut count, RES_NAME, name_section.len());
        push_section(
            &mut blob_index,
            &mut count,
            RES_IN_MEMORY_BYTECODE,
            bytecode_section.len(),
        );
        blob_index.push(BLOB_END_OF_INDEX);

        let mut resources_index: Vec<u8> = Vec::new();
        for (name, bc) in modules {
            resources_index.push(RES_START_OF_ENTRY);
            resources_index.push(RES_NAME);
            resources_index.extend_from_slice(&(name.len() as u16).to_le_bytes());
            resources_index.push(RES_IS_PYTHON_MODULE);
            resources_index.push(RES_IN_MEMORY_BYTECODE);
            resources_index.extend_from_slice(&(bc.len() as u32).to_le_bytes());
            resources_index.push(RES_END_OF_ENTRY);
        }
        resources_index.push(RES_END_OF_INDEX);

        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(BLOB_MAGIC_V3);
        out.push(count);
        out.extend_from_slice(&(blob_index.len() as u32).to_le_bytes());
        out.extend_from_slice(&(modules.len() as u32).to_le_bytes());
        out.extend_from_slice(&(resources_index.len() as u32).to_le_bytes());
        out.extend_from_slice(&blob_index);
        out.extend_from_slice(&resources_index);
        out.extend_from_slice(&name_section);
        out.extend_from_slice(&bytecode_section);
        out
    }

    #[test]
    fn parse_count_mismatch_falls_back_to_heuristic() {
        let mut blob: Vec<u8> = build_real_v3_blob(&[V3Module {
            name: "only",
            is_package: false,
            source: None,
            bytecode: Some(b"\x00\x01__pycache__/only.pyc"),
        }]);
        let count_off: usize = BLOB_MAGIC_V3.len() + 1 + 4;
        blob[count_off..count_off + 4].copy_from_slice(&99u32.to_le_bytes());
        let parsed: PackedResourcesParse =
            parse_packed_resources(&blob).expect("must fall back, not fail");
        assert!(parsed.best_effort, "diagnostics: {:?}", parsed.diagnostics);
    }

    #[test]
    fn parse_truncated_index_falls_back_to_heuristic() {
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(BLOB_MAGIC_V3);
        blob.push(1);
        blob.extend_from_slice(&64u32.to_le_bytes());
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&64u32.to_le_bytes());
        blob.extend_from_slice(b"__pycache__/mod.pyc");
        let parsed: PackedResourcesParse =
            parse_packed_resources(&blob).expect("must fall back, not fail");
        assert!(parsed.best_effort);
        assert!(
            parsed
                .entries
                .iter()
                .any(|e| e.name.contains("__pycache__")),
            "heuristic should surface __pycache__ name"
        );
    }

    #[test]
    fn parse_blob_index_rejects_overflowing_window() {
        let region: Vec<u8> = Vec::new();
        assert!(parse_blob_index(&region, usize::MAX - 3, 8).is_none());
    }

    #[test]
    fn integer_readers_reject_overflowing_cursor() {
        let buf: [u8; 8] = [0u8; 8];
        let mut cursor16: usize = usize::MAX - 1;
        let mut cursor32: usize = usize::MAX - 3;
        let mut cursor64: usize = usize::MAX - 7;
        assert_eq!(read_u16(&buf, &mut cursor16), None);
        assert_eq!(read_u32(&buf, &mut cursor32), None);
        assert_eq!(read_u64(&buf, &mut cursor64), None);
    }

    #[test]
    fn parse_returns_none_without_v3_magic() {
        assert!(parse_packed_resources(b"pyembed-resources-0\x01\x02\x03").is_none());
    }

    #[test]
    fn extract_modules_returns_empty_without_v3_magic() {
        assert!(
            extract_modules(b"no magic at all")
                .expect("missing v3 magic is not malformed")
                .is_empty()
        );
    }

    #[test]
    fn extract_modules_errors_on_corrupt_v3_magic_region() {
        let err: ModuleExtractionError =
            extract_modules(BLOB_MAGIC_V3).expect_err("v3 magic without index must fail");
        assert_eq!(err, ModuleExtractionError::MalformedV3Resources);
    }

    #[test]
    fn parse_empty_v3_blob_is_exact_not_heuristic() {
        let blob: Vec<u8> = build_real_v3_blob(&[]);
        let parsed: PackedResourcesParse = parse_packed_resources(&blob).expect("parse");
        assert_eq!(parsed.declared_count, 0);
        assert!(parsed.entries.is_empty());
        assert!(
            !parsed.best_effort,
            "empty index is still a valid exact parse"
        );
    }
}
