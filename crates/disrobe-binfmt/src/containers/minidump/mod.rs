use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

mod carve;
mod parse;
mod pe_emit;
#[cfg(test)]
mod tests;

pub use carve::{AbsentRange, AbsentReason, CarvedModule, CoverageReport, carve_module};
pub use pe_emit::PeEmitReport;

#[cfg(test)]
pub(crate) fn hostile_named_dump(module_name: &str) -> Vec<u8> {
    let text: Vec<u8> = tests::text_fixture();
    let rdata: Vec<u8> = tests::rdata_fixture();
    let image: Vec<u8> = tests::build_mapped_pe64(&text, &rdata);
    tests::build_dump(
        module_name,
        9,
        tests::SIZE_OF_IMAGE,
        &[(tests::IMAGE_BASE, 0x3000, image)],
    )
}

pub const MINIDUMP_SIGNATURE: u32 = 0x504D_444D;
pub const MINIDUMP_VERSION: u16 = 42899;

pub(super) const HEADER_LEN: usize = 32;
pub(super) const DIRECTORY_ENTRY_LEN: usize = 12;
pub(super) const MODULE_ENTRY_LEN: usize = 108;
pub(super) const MEMORY_DESCRIPTOR_LEN: usize = 16;
pub(super) const MEMORY_DESCRIPTOR64_LEN: usize = 16;
pub(super) const MEMORY64_LIST_HEADER_LEN: usize = 16;

pub(super) const STREAM_MODULE_LIST: u32 = 4;
pub(super) const STREAM_MEMORY_LIST: u32 = 5;
pub(super) const STREAM_SYSTEM_INFO: u32 = 7;
pub(super) const STREAM_MEMORY64_LIST: u32 = 9;

pub(super) const MAX_STREAMS: u32 = 65_536;
pub(super) const MAX_MODULES: u32 = 262_144;
pub(super) const MAX_MEMORY_REGIONS: u64 = 8_000_000;
pub(super) const MAX_SIZE_OF_IMAGE: u64 = 2 * 1024 * 1024 * 1024;
pub(super) const MAX_MODULE_NAME_BYTES: u32 = 64 * 1024;
pub(super) const MAX_PDB_PATH_BYTES: usize = 4096;

pub(super) const CV_SIGNATURE_RSDS: u32 = 0x5344_5352;
pub(super) const CV_SIGNATURE_NB10: u32 = 0x3031_424E;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessorArch {
    X86,
    Amd64,
    Arm,
    Arm64,
    Ia64,
    Unknown(u16),
}

impl ProcessorArch {
    pub(super) const fn from_raw(value: u16) -> Self {
        match value {
            0 => Self::X86,
            5 => Self::Arm,
            6 => Self::Ia64,
            9 => Self::Amd64,
            12 => Self::Arm64,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn pointer_width(self) -> u8 {
        match self {
            Self::X86 | Self::Arm => 4,
            Self::Amd64 | Self::Arm64 | Self::Ia64 => 8,
            Self::Unknown(_) => 0,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::Amd64 => "amd64",
            Self::Arm => "arm",
            Self::Arm64 => "arm64",
            Self::Ia64 => "ia64",
            Self::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemorySource {
    MemoryList,
    Memory64List,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamDirEntry {
    pub stream_type: u32,
    pub data_size: u32,
    pub rva: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CvKind {
    Pdb70,
    Pdb20,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CvRecord {
    pub kind: CvKind,
    pub guid: [u8; 16],
    pub age: u32,
    pub pdb_path: String,
}

impl CvRecord {
    #[must_use]
    pub fn guid_string(&self) -> String {
        let g: &[u8; 16] = &self.guid;
        let d1: u32 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
        let d2: u16 = u16::from_le_bytes([g[4], g[5]]);
        let d3: u16 = u16::from_le_bytes([g[6], g[7]]);
        format!(
            "{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
        )
    }

    #[must_use]
    pub fn debug_identifier(&self) -> String {
        let g: &[u8; 16] = &self.guid;
        let d1: u32 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
        let d2: u16 = u16::from_le_bytes([g[4], g[5]]);
        let d3: u16 = u16::from_le_bytes([g[6], g[7]]);
        format!(
            "{d1:08X}{d2:04X}{d3:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:X}",
            g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15], self.age
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinidumpModule {
    pub base_of_image: u64,
    pub size_of_image: u32,
    pub checksum: u32,
    pub timestamp: u32,
    pub name: String,
    pub cv_record: Option<CvRecord>,
}

impl MinidumpModule {
    #[must_use]
    pub fn file_name(&self) -> String {
        let base: &str = self
            .name
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(self.name.as_str());
        if base.is_empty() {
            format!("module_{:016x}.bin", self.base_of_image)
        } else {
            base.to_owned()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinidumpMemoryRegion {
    pub start_va: u64,
    pub data_size: u64,
    pub file_offset: u64,
    pub file_available: u64,
    pub source: MemorySource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinidumpFile {
    pub version: u32,
    pub arch: ProcessorArch,
    pub pointer_width: u8,
    pub stream_directory_rva: u32,
    pub number_of_streams: u32,
    pub streams: Vec<StreamDirEntry>,
    pub modules: Vec<MinidumpModule>,
    pub memory_regions: Vec<MinidumpMemoryRegion>,
    pub notes: Vec<String>,
}

#[derive(Debug)]
pub(super) struct MinidumpHeader {
    pub version: u32,
    pub number_of_streams: u32,
    pub stream_directory_rva: u32,
}

#[inline]
pub(super) fn u16_le(bytes: &[u8], at: usize) -> Option<u16> {
    let s: &[u8] = bytes.get(at..at + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
pub(super) fn u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    let s: &[u8] = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
pub(super) fn u64_le(bytes: &[u8], at: usize) -> Option<u64> {
    let s: &[u8] = bytes.get(at..at + 8)?;
    Some(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

#[must_use]
pub fn detect_minidump(bytes: &[u8]) -> bool {
    let Some(signature): Option<u32> = u32_le(bytes, 0) else {
        return false;
    };
    if signature != MINIDUMP_SIGNATURE {
        return false;
    }
    let Some(version): Option<u32> = u32_le(bytes, 4) else {
        return false;
    };
    if (version & 0xFFFF) as u16 != MINIDUMP_VERSION {
        return false;
    }
    let Some(number_of_streams): Option<u32> = u32_le(bytes, 8) else {
        return false;
    };
    if number_of_streams > MAX_STREAMS {
        return false;
    }
    let Some(dir_rva): Option<u32> = u32_le(bytes, 12) else {
        return false;
    };
    let Some(table_bytes): Option<u64> =
        u64::from(number_of_streams).checked_mul(DIRECTORY_ENTRY_LEN as u64)
    else {
        return false;
    };
    let Some(dir_end): Option<u64> = u64::from(dir_rva).checked_add(table_bytes) else {
        return false;
    };
    dir_end <= bytes.len() as u64
}

pub fn parse_minidump(bytes: &[u8]) -> Result<MinidumpFile> {
    let header: MinidumpHeader = parse::parse_header(bytes)?;
    let streams: Vec<StreamDirEntry> = parse::read_directory(bytes, &header)?;
    let mut notes: Vec<String> = Vec::new();

    let arch: ProcessorArch = streams
        .iter()
        .find(|s: &&StreamDirEntry| s.stream_type == STREAM_SYSTEM_INFO)
        .and_then(|s: &StreamDirEntry| parse::parse_system_info(bytes, s))
        .unwrap_or(ProcessorArch::Unknown(0xFFFF));

    let modules: Vec<MinidumpModule> = if let Some(stream) = streams
        .iter()
        .find(|s: &&StreamDirEntry| s.stream_type == STREAM_MODULE_LIST)
    {
        parse::parse_module_list(bytes, stream, &mut notes)?
    } else {
        notes.push("minidump: no ModuleListStream present".to_owned());
        Vec::new()
    };

    let mut regions: Vec<MinidumpMemoryRegion> = Vec::new();
    if let Some(stream) = streams
        .iter()
        .find(|s: &&StreamDirEntry| s.stream_type == STREAM_MEMORY_LIST)
    {
        parse::parse_memory_list(bytes, stream, &mut regions, &mut notes);
    }
    if let Some(stream) = streams
        .iter()
        .find(|s: &&StreamDirEntry| s.stream_type == STREAM_MEMORY64_LIST)
        && let Err(e) = parse::parse_memory64_list(bytes, stream, &mut regions, &mut notes)
    {
        notes.push(format!("minidump: Memory64List parse aborted: {e}"));
    }
    regions.sort_by_key(|r: &MinidumpMemoryRegion| r.start_va);

    Ok(MinidumpFile {
        version: header.version,
        arch,
        pointer_width: arch.pointer_width(),
        stream_directory_rva: header.stream_directory_rva,
        number_of_streams: header.number_of_streams,
        streams,
        modules,
        memory_regions: regions,
        notes,
    })
}

#[must_use]
pub fn minidump_extent(bytes: &[u8]) -> Option<usize> {
    let file: MinidumpFile = parse_minidump(bytes).ok()?;
    let mut end: u64 = HEADER_LEN as u64;
    let table_bytes: u64 =
        u64::from(file.number_of_streams).checked_mul(DIRECTORY_ENTRY_LEN as u64)?;
    end = end.max(u64::from(file.stream_directory_rva).checked_add(table_bytes)?);
    for stream in &file.streams {
        end = end.max(u64::from(stream.rva).checked_add(u64::from(stream.data_size))?);
    }
    for region in &file.memory_regions {
        end = end.max(region.file_offset.checked_add(region.file_available)?);
    }
    let extent: usize = usize::try_from(end).ok()?;
    Some(extent.min(bytes.len()))
}

pub(super) fn err(message: impl Into<String>) -> Error {
    Error::Minidump(message.into())
}
