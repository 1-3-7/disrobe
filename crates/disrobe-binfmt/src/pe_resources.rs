use std::collections::BTreeMap;

use object::LittleEndian;
use object::read::pe::{
    ImageNtHeaders, PeFile, ResourceDirectory, ResourceDirectoryEntryData, ResourceDirectoryTable,
    ResourceNameOrId,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_ENTRIES: usize = 65_536;
const FIXED_FILE_INFO_SIGNATURE: u32 = 0xFEEF_04BD;
const RT_STRING: u16 = 6;
const RT_GROUP_ICON: u16 = 14;
const RT_VERSION: u16 = 16;
const RT_MANIFEST: u16 = 24;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(untagged)]
pub enum ResourceId {
    Id(u16),
    Name(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceEntry {
    pub kind: ResourceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind_name: Option<&'static str>,
    pub name: ResourceId,
    pub language: u16,
    pub rva: u32,
    pub size: usize,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<&'static str>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct VersionInfo {
    pub file_version: String,
    pub product_version: String,
    pub flags_mask: u32,
    pub flags: u32,
    pub os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
    pub translations: Vec<(u16, u16)>,
    pub strings: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StringTable {
    pub language: u16,
    pub strings: BTreeMap<u32, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Manifest {
    pub language: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assembly_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_access: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpi_aware: Option<String>,
    pub dependencies: Vec<String>,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IconImage {
    pub width: u16,
    pub height: u16,
    pub bit_count: u16,
    pub size: u32,
    pub icon_id: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IconGroup {
    pub name: ResourceId,
    pub language: u16,
    pub images: Vec<IconImage>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ResourceReport {
    pub entries: Vec<ResourceEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<VersionInfo>,
    pub string_tables: Vec<StringTable>,
    pub manifests: Vec<Manifest>,
    pub icon_groups: Vec<IconGroup>,
    pub problems: Vec<String>,
}

#[must_use]
pub const fn kind_name(id: u16) -> Option<&'static str> {
    Some(match id {
        1 => "CURSOR",
        2 => "BITMAP",
        3 => "ICON",
        4 => "MENU",
        5 => "DIALOG",
        6 => "STRING",
        7 => "FONTDIR",
        8 => "FONT",
        9 => "ACCELERATOR",
        10 => "RCDATA",
        11 => "MESSAGETABLE",
        12 => "GROUP_CURSOR",
        14 => "GROUP_ICON",
        16 => "VERSION",
        17 => "DLGINCLUDE",
        19 => "PLUGPLAY",
        20 => "VXD",
        21 => "ANICURSOR",
        22 => "ANIICON",
        23 => "HTML",
        24 => "MANIFEST",
        _ => return None,
    })
}

fn sniff(data: &[u8]) -> Option<&'static str> {
    let signatures: [(&[u8], &'static str); 12] = [
        (b"MZ", "pe"),
        (b"PK\x03\x04", "zip"),
        (b"\x7fELF", "elf"),
        (b"%PDF", "pdf"),
        (b"\x89PNG", "png"),
        (b"7z\xbc\xaf\x27\x1c", "7z"),
        (b"Rar!", "rar"),
        (b"\x1f\x8b", "gzip"),
        (b"MSCF", "cab"),
        (b"<?xml", "xml"),
        (b"\xEF\xBB\xBF<?xml", "xml"),
        (b"BZh", "bzip2"),
    ];
    signatures
        .iter()
        .find(|(magic, _)| data.starts_with(magic))
        .map(|(_, name)| *name)
}

fn hex(digest: &[u8]) -> String {
    use std::fmt::Write as _;
    digest
        .iter()
        .fold(String::new(), |mut out: String, byte: &u8| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn utf16(bytes: &[u8]) -> String {
    let units = bytes
        .chunks_exact(2)
        .map(|pair: &[u8]| u16::from_le_bytes([pair[0], pair[1]]));
    char::decode_utf16(units)
        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

fn word(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at.checked_add(2)?)
        .map(|raw: &[u8]| u16::from_le_bytes([raw[0], raw[1]]))
}

fn dword(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at.checked_add(4)?)
        .map(|raw: &[u8]| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

pub fn pe_resources(bytes: &[u8]) -> std::result::Result<ResourceReport, String> {
    match object::FileKind::parse(bytes) {
        Ok(object::FileKind::Pe32) => read::<object::pe::ImageNtHeaders32>(bytes),
        Ok(object::FileKind::Pe64) => read::<object::pe::ImageNtHeaders64>(bytes),
        Ok(other) => Err(format!("{other:?} is not a PE image")),
        Err(error) => Err(error.to_string()),
    }
}

#[must_use]
pub fn resource_data<'a>(bytes: &'a [u8], entry: &ResourceEntry) -> Option<&'a [u8]> {
    match object::FileKind::parse(bytes).ok()? {
        object::FileKind::Pe32 => {
            data_at::<object::pe::ImageNtHeaders32>(bytes, entry.rva, entry.size)
        }
        object::FileKind::Pe64 => {
            data_at::<object::pe::ImageNtHeaders64>(bytes, entry.rva, entry.size)
        }
        _ => None,
    }
}

fn data_at<Pe: ImageNtHeaders>(bytes: &[u8], rva: u32, size: usize) -> Option<&[u8]> {
    let file: PeFile<'_, Pe> = PeFile::parse(bytes).ok()?;
    file.section_table()
        .pe_data_at(bytes, rva)
        .and_then(|rest: &[u8]| rest.get(..size))
}

fn id_of(directory: ResourceDirectory<'_>, name: ResourceNameOrId) -> ResourceId {
    match name {
        ResourceNameOrId::Id(id) => ResourceId::Id(id),
        ResourceNameOrId::Name(name) => ResourceId::Name(
            name.to_string_lossy(directory)
                .unwrap_or_else(|_| "<unreadable name>".to_owned()),
        ),
    }
}

fn read<Pe: ImageNtHeaders>(bytes: &[u8]) -> std::result::Result<ResourceReport, String> {
    let file: PeFile<'_, Pe> = PeFile::parse(bytes).map_err(|e| e.to_string())?;
    let sections = file.section_table();
    let mut report: ResourceReport = ResourceReport::default();
    let directory: ResourceDirectory<'_> =
        match file.data_directories().resource_directory(bytes, &sections) {
            Ok(Some(directory)) => directory,
            Ok(None) => return Ok(report),
            Err(error) => return Err(error.to_string()),
        };
    let types: ResourceDirectoryTable<'_> = directory.root().map_err(|e| e.to_string())?;
    let mut blobs: Vec<(ResourceEntry, &[u8])> = Vec::new();
    'walk: for type_entry in types.entries {
        let kind: ResourceId = id_of(directory, type_entry.name_or_id());
        let Ok(ResourceDirectoryEntryData::Table(names)) = type_entry.data(directory) else {
            report
                .problems
                .push(format!("resource type {kind:?} has no name table"));
            continue;
        };
        for name_entry in names.entries {
            let name: ResourceId = id_of(directory, name_entry.name_or_id());
            let Ok(ResourceDirectoryEntryData::Table(languages)) = name_entry.data(directory)
            else {
                report
                    .problems
                    .push(format!("resource {kind:?}/{name:?} has no language table"));
                continue;
            };
            for language_entry in languages.entries {
                if blobs.len() >= MAX_ENTRIES {
                    report.problems.push(format!(
                        "more than {MAX_ENTRIES} resources; the rest are not listed"
                    ));
                    break 'walk;
                }
                let language: u16 = match language_entry.name_or_id() {
                    ResourceNameOrId::Id(id) => id,
                    ResourceNameOrId::Name(_) => 0,
                };
                let Ok(ResourceDirectoryEntryData::Data(data)) = language_entry.data(directory)
                else {
                    report.problems.push(format!(
                        "resource {kind:?}/{name:?}/{language} has no data entry"
                    ));
                    continue;
                };
                let rva: u32 = data.offset_to_data.get(LittleEndian);
                let size: usize = data.size.get(LittleEndian) as usize;
                let Some(content): Option<&[u8]> = sections
                    .pe_data_at(bytes, rva)
                    .and_then(|rest: &[u8]| rest.get(..size))
                else {
                    report.problems.push(format!(
                        "resource {kind:?}/{name:?}/{language} at RVA 0x{rva:x} ({size} bytes) lies outside the image"
                    ));
                    continue;
                };
                let kind_label: Option<&'static str> = match kind {
                    ResourceId::Id(id) => kind_name(id),
                    ResourceId::Name(_) => None,
                };
                blobs.push((
                    ResourceEntry {
                        kind: kind.clone(),
                        kind_name: kind_label,
                        name: name.clone(),
                        language,
                        rva,
                        size,
                        sha256: hex(&Sha256::digest(content)),
                        content: sniff(content),
                    },
                    content,
                ));
            }
        }
    }
    for (entry, content) in &blobs {
        match entry.kind {
            ResourceId::Id(RT_VERSION) if report.version.is_none() => match version_info(content) {
                Some(info) => report.version = Some(info),
                None => report
                    .problems
                    .push("VERSIONINFO resource does not decode".to_owned()),
            },
            ResourceId::Id(RT_STRING) => {
                if let ResourceId::Id(block) = entry.name {
                    let strings: BTreeMap<u32, String> = string_block(block, content);
                    match report
                        .string_tables
                        .iter_mut()
                        .find(|table: &&mut StringTable| table.language == entry.language)
                    {
                        Some(table) => table.strings.extend(strings),
                        None => report.string_tables.push(StringTable {
                            language: entry.language,
                            strings,
                        }),
                    }
                }
            }
            ResourceId::Id(RT_MANIFEST) => {
                report.manifests.push(manifest(entry.language, content));
            }
            ResourceId::Id(RT_GROUP_ICON) => {
                report.icon_groups.push(IconGroup {
                    name: entry.name.clone(),
                    language: entry.language,
                    images: icon_group(content),
                });
            }
            _ => {}
        }
    }
    report
        .string_tables
        .sort_by_key(|table: &StringTable| table.language);
    report.entries = blobs.into_iter().map(|(entry, _)| entry).collect();
    Ok(report)
}

fn string_block(block: u16, data: &[u8]) -> BTreeMap<u32, String> {
    let mut strings: BTreeMap<u32, String> = BTreeMap::new();
    let base: u32 = u32::from(block.saturating_sub(1)) * 16;
    let mut at: usize = 0;
    for index in 0..16u32 {
        let Some(length): Option<u16> = word(data, at) else {
            break;
        };
        at += 2;
        let end: usize = at + usize::from(length) * 2;
        let Some(text): Option<&[u8]> = data.get(at..end) else {
            break;
        };
        if length > 0 {
            strings.insert(base + index, utf16(text));
        }
        at = end;
    }
    strings
}

fn attribute(text: &str, element: &str, name: &str) -> Option<String> {
    let start: usize = text.find(&format!("<{element}"))?;
    let end: usize = start + text[start..].find('>')?;
    let tag: &str = &text[start..end];
    let key: String = format!("{name}=\"");
    let value_start: usize = tag.find(&key)? + key.len();
    let value_end: usize = value_start + tag[value_start..].find('"')?;
    Some(tag[value_start..value_end].to_owned())
}

fn manifest(language: u16, data: &[u8]) -> Manifest {
    let text: String =
        String::from_utf8_lossy(data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data)).into_owned();
    let dependencies: Vec<String> = text
        .match_indices("<dependentAssembly")
        .filter_map(|(at, _)| attribute(&text[at..], "assemblyIdentity", "name"))
        .collect();
    let dpi_aware: Option<String> = text.find("<dpiAware").and_then(|at| {
        let open: usize = at + text[at..].find('>')? + 1;
        let close: usize = open + text[open..].find('<')?;
        Some(text[open..close].trim().to_owned())
    });
    Manifest {
        language,
        assembly_name: attribute(&text, "assemblyIdentity", "name"),
        execution_level: attribute(&text, "requestedExecutionLevel", "level"),
        ui_access: attribute(&text, "requestedExecutionLevel", "uiAccess")
            .map(|value: String| value.eq_ignore_ascii_case("true")),
        dpi_aware,
        dependencies,
        text,
    }
}

fn icon_group(data: &[u8]) -> Vec<IconImage> {
    let count: usize = word(data, 4).map_or(0, usize::from);
    (0..count)
        .map_while(|index: usize| {
            let at: usize = 6 + index * 14;
            let raw: &[u8] = data.get(at..at + 14)?;
            let dimension = |value: u8| if value == 0 { 256 } else { u16::from(value) };
            Some(IconImage {
                width: dimension(raw[0]),
                height: dimension(raw[1]),
                bit_count: word(raw, 6)?,
                size: dword(raw, 8)?,
                icon_id: word(raw, 12)?,
            })
        })
        .collect()
}

struct Node<'a> {
    key: String,
    value: &'a [u8],
    text: bool,
    children: &'a [u8],
}

fn node(data: &[u8]) -> Option<Node<'_>> {
    let length: usize = usize::from(word(data, 0)?);
    let value_length: u16 = word(data, 2)?;
    let text: bool = word(data, 4)? == 1;
    let block: &[u8] = data.get(..length.min(data.len()))?;
    let mut at: usize = 6;
    let mut key_units: Vec<u16> = Vec::new();
    loop {
        let unit: u16 = word(block, at)?;
        at += 2;
        if unit == 0 {
            break;
        }
        key_units.push(unit);
    }
    let key: String = String::from_utf16_lossy(&key_units);
    at = at.next_multiple_of(4);
    let value_bytes: usize = if text {
        usize::from(value_length) * 2
    } else {
        usize::from(value_length)
    };
    let value_end: usize = (at + value_bytes).min(block.len());
    let value: &[u8] = block.get(at.min(block.len())..value_end)?;
    let children_start: usize = value_end.next_multiple_of(4).min(block.len());
    Some(Node {
        key,
        value,
        text,
        children: &block[children_start..],
    })
}

fn children(data: &[u8]) -> Vec<Node<'_>> {
    let mut out: Vec<Node<'_>> = Vec::new();
    let mut rest: &[u8] = data;
    while rest.len() >= 6 && out.len() < 4096 {
        let Some(length): Option<u16> = word(rest, 0) else {
            break;
        };
        let length: usize = usize::from(length);
        if length < 6 {
            break;
        }
        if let Some(child) = node(rest) {
            out.push(child);
        }
        let advance: usize = length.next_multiple_of(4);
        if advance >= rest.len() {
            break;
        }
        rest = &rest[advance..];
    }
    out
}

fn version_info(data: &[u8]) -> Option<VersionInfo> {
    let root: Node<'_> = node(data)?;
    if root.key != "VS_VERSION_INFO" || dword(root.value, 0)? != FIXED_FILE_INFO_SIGNATURE {
        return None;
    }
    let fixed: &[u8] = root.value;
    let split = |high: u32, low: u32| {
        format!(
            "{}.{}.{}.{}",
            high >> 16,
            high & 0xFFFF,
            low >> 16,
            low & 0xFFFF
        )
    };
    let mut info: VersionInfo = VersionInfo {
        file_version: split(dword(fixed, 8)?, dword(fixed, 12)?),
        product_version: split(dword(fixed, 16)?, dword(fixed, 20)?),
        flags_mask: dword(fixed, 24)?,
        flags: dword(fixed, 28)?,
        os: dword(fixed, 32)?,
        file_type: dword(fixed, 36)?,
        file_subtype: dword(fixed, 40)?,
        ..VersionInfo::default()
    };
    for section in children(root.children) {
        match section.key.as_str() {
            "StringFileInfo" => {
                for table in children(section.children) {
                    let mut values: BTreeMap<String, String> = BTreeMap::new();
                    for pair in children(table.children) {
                        let text: String = if pair.text {
                            utf16(pair.value)
                        } else {
                            String::from_utf8_lossy(pair.value).into_owned()
                        };
                        values.insert(pair.key, text.trim_end_matches('\0').to_owned());
                    }
                    info.strings.insert(table.key.to_lowercase(), values);
                }
            }
            "VarFileInfo" => {
                for var in children(section.children) {
                    if var.key == "Translation" {
                        info.translations = var
                            .value
                            .chunks_exact(4)
                            .map(|pair: &[u8]| {
                                (
                                    u16::from_le_bytes([pair[0], pair[1]]),
                                    u16::from_le_bytes([pair[2], pair[3]]),
                                )
                            })
                            .collect();
                    }
                }
            }
            _ => {}
        }
    }
    Some(info)
}
