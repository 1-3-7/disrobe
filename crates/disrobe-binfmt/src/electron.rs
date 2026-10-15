use memchr::memmem;
use object::LittleEndian;
use object::read::pe::{
    ImageNtHeaders, PeFile, ResourceDirectory, ResourceDirectoryEntryData, ResourceDirectoryTable,
    ResourceNameOrId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::asar::{self, AsarEntry, AsarLayout};
use crate::error::Result;

pub const FUSE_SENTINEL: &[u8] = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";
const MAX_WIRES: usize = 32;
const MAX_FAT_SLICES: u32 = 32;
const MAX_INTEGRITY_RESOURCE: usize = 1024 * 1024;
const MAX_RESOURCE_ENTRIES: usize = 4096;

const FUSE_V1_NAMES: [&str; 9] = [
    "RunAsNode",
    "EnableCookieEncryption",
    "EnableNodeOptionsEnvironmentVariable",
    "EnableNodeCliInspectArguments",
    "EnableEmbeddedAsarIntegrityValidation",
    "OnlyLoadAppFromAsar",
    "LoadBrowserProcessSpecificV8Snapshot",
    "GrantFileProtocolExtraPrivileges",
    "WasmTrapHandlers",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FuseState {
    Disabled,
    Enabled,
    Removed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fuse {
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<&'static str>,
    pub state: FuseState,
    pub raw: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FuseWire {
    pub offset: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slice: Option<String>,
    pub version: u8,
    pub declared_length: u8,
    pub fuses: Vec<Fuse>,
    pub complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntegritySource {
    PeResource,
    InfoPlist,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeclaredIntegrity {
    pub file: String,
    pub algorithm: String,
    pub hash: String,
    pub source: IntegritySource,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ExecutableReport {
    pub fuse_wires: Vec<FuseWire>,
    pub declared_integrity: Vec<DeclaredIntegrity>,
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileStatus {
    Match,
    Mismatch,
    NoIntegrity,
    UnsupportedAlgorithm,
    MalformedBlocks,
    OutOfBounds,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileCheck {
    pub path: String,
    pub size: u64,
    pub status: FileStatus,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mismatched_blocks: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchiveIntegrity {
    pub header_sha256: String,
    pub header_size: usize,
    pub files: Vec<FileCheck>,
    pub unpacked: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ResourceRecord {
    file: String,
    alg: String,
    value: String,
}

#[must_use]
pub fn inspect_executable(bytes: &[u8]) -> ExecutableReport {
    let mut report: ExecutableReport = ExecutableReport {
        fuse_wires: fuse_wires(bytes),
        ..ExecutableReport::default()
    };
    match object::FileKind::parse(bytes) {
        Ok(object::FileKind::Pe32) => {
            pe_integrity::<object::pe::ImageNtHeaders32>(bytes, &mut report);
        }
        Ok(object::FileKind::Pe64) => {
            pe_integrity::<object::pe::ImageNtHeaders64>(bytes, &mut report);
        }
        _ => {}
    }
    report
}

#[must_use]
pub fn fuse_wires(bytes: &[u8]) -> Vec<FuseWire> {
    let slices: Vec<(u64, u64, String)> = fat_slices(bytes);
    let mut wires: Vec<FuseWire> = Vec::new();
    for offset in memmem::find_iter(bytes, FUSE_SENTINEL).take(MAX_WIRES) {
        let header: usize = offset + FUSE_SENTINEL.len();
        let (Some(&version), Some(&declared_length)): (Option<&u8>, Option<&u8>) =
            (bytes.get(header), bytes.get(header + 1))
        else {
            continue;
        };
        let body: &[u8] = bytes
            .get(header + 2..)
            .map(|rest: &[u8]| &rest[..rest.len().min(usize::from(declared_length))])
            .unwrap_or_default();
        let fuses: Vec<Fuse> = body
            .iter()
            .enumerate()
            .map(|(index, &raw): (usize, &u8)| Fuse {
                index,
                name: (version == 1)
                    .then(|| FUSE_V1_NAMES.get(index).copied())
                    .flatten(),
                state: match raw {
                    0x30 => FuseState::Disabled,
                    0x31 => FuseState::Enabled,
                    0x72 => FuseState::Removed,
                    _ => FuseState::Unknown,
                },
                raw,
            })
            .collect();
        let file_offset: u64 = offset as u64;
        wires.push(FuseWire {
            offset: file_offset,
            slice: slices
                .iter()
                .find(|(start, size, _)| file_offset >= *start && file_offset - start < *size)
                .map(|(_, _, name)| name.clone()),
            version,
            declared_length,
            complete: fuses.len() == usize::from(declared_length),
            fuses,
        });
    }
    wires
}

fn fat_slices(bytes: &[u8]) -> Vec<(u64, u64, String)> {
    let word = |at: usize| -> Option<u32> {
        bytes
            .get(at..at + 4)
            .map(|raw: &[u8]| u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
    };
    let long = |at: usize| -> Option<u64> {
        let high: u64 = u64::from(word(at)?);
        let low: u64 = u64::from(word(at + 4)?);
        Some((high << 32) | low)
    };
    let (Some(magic), Some(count)): (Option<u32>, Option<u32>) = (word(0), word(4)) else {
        return Vec::new();
    };
    let wide: bool = match magic {
        0xCAFE_BABE => false,
        0xCAFE_BABF => true,
        _ => return Vec::new(),
    };
    if count == 0 || count > MAX_FAT_SLICES {
        return Vec::new();
    }
    let stride: usize = if wide { 32 } else { 20 };
    let mut slices: Vec<(u64, u64, String)> = Vec::new();
    for index in 0..count as usize {
        let at: usize = 8 + index * stride;
        let Some(cpu): Option<u32> = word(at) else {
            return Vec::new();
        };
        let (offset, size): (Option<u64>, Option<u64>) = if wide {
            (long(at + 8), long(at + 16))
        } else {
            (word(at + 8).map(u64::from), word(at + 12).map(u64::from))
        };
        let (Some(offset), Some(size)): (Option<u64>, Option<u64>) = (offset, size) else {
            return Vec::new();
        };
        if offset
            .checked_add(size)
            .is_none_or(|end: u64| end > bytes.len() as u64)
        {
            return Vec::new();
        }
        let name: String = match cpu {
            0x0000_0007 => "x86".to_owned(),
            0x0100_0007 => "x86_64".to_owned(),
            0x0000_000C => "arm".to_owned(),
            0x0100_000C => "arm64".to_owned(),
            0x0200_000C => "arm64_32".to_owned(),
            other => format!("cpu 0x{other:08x}"),
        };
        slices.push((offset, size, name));
    }
    slices
}

fn pe_integrity<Pe: ImageNtHeaders>(bytes: &[u8], report: &mut ExecutableReport) {
    let file: PeFile<'_, Pe> = match PeFile::parse(bytes) {
        Ok(file) => file,
        Err(error) => {
            report.problems.push(format!("PE parse: {error}"));
            return;
        }
    };
    let sections = file.section_table();
    let directory: ResourceDirectory<'_> =
        match file.data_directories().resource_directory(bytes, &sections) {
            Ok(Some(directory)) => directory,
            Ok(None) => return,
            Err(error) => {
                report.problems.push(format!("PE resources: {error}"));
                return;
            }
        };
    let Some(types): Option<ResourceDirectoryTable<'_>> = directory.root().ok() else {
        report
            .problems
            .push("PE resource root is unreadable".to_owned());
        return;
    };
    for type_entry in types.entries.iter().take(MAX_RESOURCE_ENTRIES) {
        if !named(&directory, type_entry.name_or_id(), "INTEGRITY") {
            continue;
        }
        let Ok(ResourceDirectoryEntryData::Table(names)) = type_entry.data(directory) else {
            continue;
        };
        for name_entry in names.entries.iter().take(MAX_RESOURCE_ENTRIES) {
            if !named(&directory, name_entry.name_or_id(), "ELECTRONASAR") {
                continue;
            }
            let Ok(ResourceDirectoryEntryData::Table(languages)) = name_entry.data(directory)
            else {
                continue;
            };
            for language in languages.entries.iter().take(MAX_RESOURCE_ENTRIES) {
                let Ok(ResourceDirectoryEntryData::Data(data)) = language.data(directory) else {
                    continue;
                };
                let rva: u32 = data.offset_to_data.get(LittleEndian);
                let size: usize = data.size.get(LittleEndian) as usize;
                let Some(content): Option<&[u8]> = sections
                    .pe_data_at(bytes, rva)
                    .and_then(|rest: &[u8]| rest.get(..size.min(MAX_INTEGRITY_RESOURCE)))
                else {
                    report.problems.push(format!(
                        "INTEGRITY/ELECTRONASAR resource at RVA 0x{rva:x} lies outside the image"
                    ));
                    continue;
                };
                match serde_json::from_slice::<Vec<ResourceRecord>>(content) {
                    Ok(records) => report.declared_integrity.extend(records.into_iter().map(
                        |record: ResourceRecord| DeclaredIntegrity {
                            file: record.file,
                            algorithm: record.alg,
                            hash: record.value,
                            source: IntegritySource::PeResource,
                        },
                    )),
                    Err(error) => report.problems.push(format!(
                        "INTEGRITY/ELECTRONASAR resource is not valid JSON: {error}"
                    )),
                }
            }
        }
    }
}

fn named(directory: &ResourceDirectory<'_>, name: ResourceNameOrId, expected: &str) -> bool {
    match name {
        ResourceNameOrId::Name(name) => name
            .to_string_lossy(*directory)
            .is_ok_and(|text: String| text.eq_ignore_ascii_case(expected)),
        ResourceNameOrId::Id(_) => false,
    }
}

pub fn declared_integrity_from_plist(
    bytes: &[u8],
) -> std::result::Result<Vec<DeclaredIntegrity>, String> {
    let value: plist::Value =
        plist::Value::from_reader(std::io::Cursor::new(bytes)).map_err(|e| e.to_string())?;
    let Some(entries) = value
        .as_dictionary()
        .and_then(|root| root.get("ElectronAsarIntegrity"))
        .and_then(plist::Value::as_dictionary)
    else {
        return Ok(Vec::new());
    };
    let mut declared: Vec<DeclaredIntegrity> = Vec::new();
    for (file, entry) in entries {
        let Some(entry) = entry.as_dictionary() else {
            continue;
        };
        let text = |key: &str| -> String {
            entry
                .get(key)
                .and_then(plist::Value::as_string)
                .unwrap_or_default()
                .to_owned()
        };
        declared.push(DeclaredIntegrity {
            file: file.clone(),
            algorithm: text("algorithm"),
            hash: text("hash"),
            source: IntegritySource::InfoPlist,
        });
    }
    Ok(declared)
}

pub fn check_archive(bytes: &[u8]) -> Result<ArchiveIntegrity> {
    let layout: AsarLayout = asar::parse(bytes)?;
    let header: &[u8] = &bytes[layout.header_json.clone()];
    let files: Vec<FileCheck> = layout
        .entries
        .iter()
        .map(|entry: &AsarEntry| check_file(bytes, &layout, entry))
        .collect();
    Ok(ArchiveIntegrity {
        header_sha256: hex(&Sha256::digest(header)),
        header_size: layout.data_offset.saturating_sub(8),
        files,
        unpacked: layout.unpacked,
    })
}

fn check_file(bytes: &[u8], layout: &AsarLayout, entry: &AsarEntry) -> FileCheck {
    let mut check: FileCheck = FileCheck {
        path: entry.path.clone(),
        size: entry.size,
        status: FileStatus::NoIntegrity,
        mismatched_blocks: Vec::new(),
    };
    let Some(integrity) = entry.integrity.as_ref() else {
        return check;
    };
    if !integrity.algorithm.eq_ignore_ascii_case("SHA256") {
        check.status = FileStatus::UnsupportedAlgorithm;
        return check;
    }
    let Ok(content): Result<&[u8]> = asar::read_entry(bytes, layout, entry) else {
        check.status = FileStatus::OutOfBounds;
        return check;
    };
    let Ok(block_size): std::result::Result<usize, _> = usize::try_from(integrity.block_size)
    else {
        check.status = FileStatus::MalformedBlocks;
        return check;
    };
    let expected_blocks: usize = if content.is_empty() || block_size == 0 {
        1
    } else {
        content.len().div_ceil(block_size)
    };
    if block_size == 0 || integrity.blocks.len() != expected_blocks {
        check.status = FileStatus::MalformedBlocks;
        return check;
    }
    let chunks: Vec<&[u8]> = if content.is_empty() {
        vec![content]
    } else {
        content.chunks(block_size).collect()
    };
    for (index, (chunk, declared)) in chunks.iter().zip(&integrity.blocks).enumerate() {
        if !hex(&Sha256::digest(chunk)).eq_ignore_ascii_case(declared) {
            check.mismatched_blocks.push(index);
        }
    }
    let whole: bool = hex(&Sha256::digest(content)).eq_ignore_ascii_case(&integrity.hash);
    check.status = if whole && check.mismatched_blocks.is_empty() {
        FileStatus::Match
    } else {
        FileStatus::Mismatch
    };
    check
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
