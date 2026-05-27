use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const FAT_MAGIC_BE: u32 = 0xCAFE_BABE;
pub const FAT_MAGIC_LE: u32 = 0xBEBA_FECA;
pub const FAT_MAGIC_64_BE: u32 = 0xCAFE_BABF;
pub const FAT_MAGIC_64_LE: u32 = 0xBFBA_FECA;
pub const MH_MAGIC_32: u32 = 0xFEED_FACE;
pub const MH_CIGAM_32: u32 = 0xCEFA_EDFE;
pub const MH_MAGIC_64: u32 = 0xFEED_FACF;
pub const MH_CIGAM_64: u32 = 0xCFFA_EDFE;

pub const LC_SEGMENT: u32 = 0x1;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2C;
pub const LC_CODE_SIGNATURE: u32 = 0x1D;
pub const LC_REQ_DYLD: u32 = 0x8000_0000;

pub const MACH_HEADER_32_SIZE: usize = 28;
pub const MACH_HEADER_64_SIZE: usize = 32;

const SECTION_64_SIZE: usize = 80;
const SECTION_32_SIZE: usize = 68;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CpuKind {
    X86,
    X86_64,
    Arm,
    Arm64,
    Arm64_32,
    PowerPc,
    PowerPc64,
    Unknown(u32),
}

impl CpuKind {
    #[inline]
    #[must_use]
    pub const fn from_cputype(raw: u32) -> Self {
        match raw {
            0x0000_0007 => Self::X86,
            0x0100_0007 => Self::X86_64,
            0x0000_000C => Self::Arm,
            0x0100_000C => Self::Arm64,
            0x0200_000C => Self::Arm64_32,
            0x0000_0012 => Self::PowerPc,
            0x0100_0012 => Self::PowerPc64,
            other => Self::Unknown(other),
        }
    }

    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "arm",
            Self::Arm64 => "arm64",
            Self::Arm64_32 => "arm64_32",
            Self::PowerPc => "ppc",
            Self::PowerPc64 => "ppc64",
            Self::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Bitness {
    Bits32,
    Bits64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FatArchEntry {
    pub cpu: CpuKind,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceHeader {
    pub cpu: CpuKind,
    pub bitness: Bitness,
    pub endian: Endian,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub filetype: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub seg: String,
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub sections: Vec<Section>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub data_offset: usize,
}

#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionInfo {
    pub crypt_off: u32,
    pub crypt_size: u32,
    pub crypt_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedSlice {
    pub header: SliceHeader,
    pub segments: Vec<Segment>,
    pub load_commands: Vec<LoadCommand>,
    pub encryption: Option<EncryptionInfo>,
    pub code_signature_off: Option<u32>,
    pub code_signature_size: Option<u32>,
}

#[inline]
fn u32_le(bytes: &[u8], off: usize) -> Result<u32> {
    let slice: &[u8] = bytes.get(off..off + 4).ok_or(Error::Truncated(off))?;
    let arr: [u8; 4] = [slice[0], slice[1], slice[2], slice[3]];
    Ok(u32::from_le_bytes(arr))
}

#[inline]
fn u32_be(bytes: &[u8], off: usize) -> Result<u32> {
    let slice: &[u8] = bytes.get(off..off + 4).ok_or(Error::Truncated(off))?;
    let arr: [u8; 4] = [slice[0], slice[1], slice[2], slice[3]];
    Ok(u32::from_be_bytes(arr))
}

#[inline]
fn u64_le(bytes: &[u8], off: usize) -> Result<u64> {
    let slice: &[u8] = bytes.get(off..off + 8).ok_or(Error::Truncated(off))?;
    let mut arr: [u8; 8] = [0u8; 8];
    arr.copy_from_slice(slice);
    Ok(u64::from_le_bytes(arr))
}

#[inline]
fn u64_be(bytes: &[u8], off: usize) -> Result<u64> {
    let slice: &[u8] = bytes.get(off..off + 8).ok_or(Error::Truncated(off))?;
    let mut arr: [u8; 8] = [0u8; 8];
    arr.copy_from_slice(slice);
    Ok(u64::from_be_bytes(arr))
}

#[inline]
fn read_cstr16(bytes: &[u8], off: usize) -> Result<String> {
    let raw: &[u8] = bytes.get(off..off + 16).ok_or(Error::Truncated(off))?;
    let end: usize = raw.iter().position(|b: &u8| *b == 0).unwrap_or(raw.len());
    Ok(String::from_utf8_lossy(&raw[..end]).into_owned())
}

#[must_use]
pub fn detect_magic(bytes: &[u8]) -> Option<MachoKind> {
    if bytes.len() < 4 {
        return None;
    }
    let arr: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let be: u32 = u32::from_be_bytes(arr);
    let le: u32 = u32::from_le_bytes(arr);
    match (be, le) {
        (FAT_MAGIC_BE, _) | (_, FAT_MAGIC_LE) => Some(MachoKind::Fat32),
        (FAT_MAGIC_64_BE, _) | (_, FAT_MAGIC_64_LE) => Some(MachoKind::Fat64),
        (MH_MAGIC_32, _) => Some(MachoKind::Slice32Be),
        (MH_MAGIC_64, _) => Some(MachoKind::Slice64Be),
        (MH_CIGAM_32, _) | (_, MH_MAGIC_32) => Some(MachoKind::Slice32Le),
        (MH_CIGAM_64, _) | (_, MH_MAGIC_64) => Some(MachoKind::Slice64Le),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachoKind {
    Fat32,
    Fat64,
    Slice32Le,
    Slice32Be,
    Slice64Le,
    Slice64Be,
}

pub fn walk_fat(bytes: &[u8]) -> Result<Vec<FatArchEntry>> {
    let kind: MachoKind = detect_magic(bytes).ok_or(Error::NotMachO)?;
    let (is_fat64, nfat_arch_off): (bool, usize) = match kind {
        MachoKind::Fat32 => (false, 4),
        MachoKind::Fat64 => (true, 4),
        _ => return Err(Error::BadFatHeader("not a fat header".to_owned())),
    };
    let nfat: u32 = u32_be(bytes, nfat_arch_off)?;
    let entry_size: usize = if is_fat64 { 32 } else { 20 };
    let mut out: Vec<FatArchEntry> = Vec::with_capacity(nfat as usize);
    let mut cursor: usize = 8;
    for _ in 0..nfat {
        let cputype: u32 = u32_be(bytes, cursor)?;
        let _cpusubtype: u32 = u32_be(bytes, cursor + 4)?;
        let (offset, size): (u64, u64) = if is_fat64 {
            (u64_be(bytes, cursor + 8)?, u64_be(bytes, cursor + 16)?)
        } else {
            (
                u64::from(u32_be(bytes, cursor + 8)?),
                u64::from(u32_be(bytes, cursor + 12)?),
            )
        };
        out.push(FatArchEntry {
            cpu: CpuKind::from_cputype(cputype),
            offset,
            size,
        });
        cursor += entry_size;
    }
    Ok(out)
}

#[must_use]
pub fn slice_bytes<'a>(image: &'a [u8], entry: &FatArchEntry) -> Option<&'a [u8]> {
    let start: usize = usize::try_from(entry.offset).ok()?;
    let len: usize = usize::try_from(entry.size).ok()?;
    let end: usize = start.checked_add(len)?;
    image.get(start..end)
}

type ReadU32 = fn(&[u8], usize) -> Result<u32>;
type ReadU64 = fn(&[u8], usize) -> Result<u64>;

fn parse_segment_64(
    slice: &[u8],
    cursor: usize,
    read_u32: ReadU32,
    read_u64: ReadU64,
    idx: u32,
) -> Result<Segment> {
    let seg_name: String = read_cstr16(slice, cursor + 8)?;
    let vmaddr: u64 = read_u64(slice, cursor + 24)?;
    let vmsize: u64 = read_u64(slice, cursor + 32)?;
    let fileoff: u64 = read_u64(slice, cursor + 40)?;
    let filesize: u64 = read_u64(slice, cursor + 48)?;
    let nsects: u32 = read_u32(slice, cursor + 64)?;
    let mut sections: Vec<Section> = Vec::with_capacity(nsects as usize);
    for s in 0..nsects {
        let s_off: usize = cursor + 72 + (s as usize) * SECTION_64_SIZE;
        if s_off + SECTION_64_SIZE > slice.len() {
            return Err(Error::LoadCommand(
                idx as usize,
                "section_64 truncated".to_owned(),
            ));
        }
        let sect_name: String = read_cstr16(slice, s_off)?;
        let seg_field: String = read_cstr16(slice, s_off + 16)?;
        let addr: u64 = read_u64(slice, s_off + 32)?;
        let size: u64 = read_u64(slice, s_off + 40)?;
        let offset: u32 = read_u32(slice, s_off + 48)?;
        let sflags: u32 = read_u32(slice, s_off + 64)?;
        sections.push(Section {
            seg: seg_field,
            name: sect_name,
            addr,
            size,
            offset,
            flags: sflags,
        });
    }
    Ok(Segment {
        name: seg_name,
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        sections,
    })
}

fn parse_segment_32(slice: &[u8], cursor: usize, read_u32: ReadU32, idx: u32) -> Result<Segment> {
    let seg_name: String = read_cstr16(slice, cursor + 8)?;
    let vmaddr: u32 = read_u32(slice, cursor + 24)?;
    let vmsize: u32 = read_u32(slice, cursor + 28)?;
    let fileoff: u32 = read_u32(slice, cursor + 32)?;
    let filesize: u32 = read_u32(slice, cursor + 36)?;
    let nsects: u32 = read_u32(slice, cursor + 48)?;
    let mut sections: Vec<Section> = Vec::with_capacity(nsects as usize);
    for s in 0..nsects {
        let s_off: usize = cursor + 56 + (s as usize) * SECTION_32_SIZE;
        if s_off + SECTION_32_SIZE > slice.len() {
            return Err(Error::LoadCommand(
                idx as usize,
                "section_32 truncated".to_owned(),
            ));
        }
        let sect_name: String = read_cstr16(slice, s_off)?;
        let seg_field: String = read_cstr16(slice, s_off + 16)?;
        let addr: u32 = read_u32(slice, s_off + 32)?;
        let size: u32 = read_u32(slice, s_off + 36)?;
        let offset: u32 = read_u32(slice, s_off + 40)?;
        let sflags: u32 = read_u32(slice, s_off + 56)?;
        sections.push(Section {
            seg: seg_field,
            name: sect_name,
            addr: u64::from(addr),
            size: u64::from(size),
            offset,
            flags: sflags,
        });
    }
    Ok(Segment {
        name: seg_name,
        vmaddr: u64::from(vmaddr),
        vmsize: u64::from(vmsize),
        fileoff: u64::from(fileoff),
        filesize: u64::from(filesize),
        sections,
    })
}

pub fn parse_slice(slice: &[u8]) -> Result<ParsedSlice> {
    let kind: MachoKind = detect_magic(slice).ok_or(Error::NotMachO)?;
    let (bitness, endian): (Bitness, Endian) = match kind {
        MachoKind::Slice32Le => (Bitness::Bits32, Endian::Little),
        MachoKind::Slice32Be => (Bitness::Bits32, Endian::Big),
        MachoKind::Slice64Le => (Bitness::Bits64, Endian::Little),
        MachoKind::Slice64Be => (Bitness::Bits64, Endian::Big),
        _ => return Err(Error::NotMachO),
    };
    let read_u32: ReadU32 = match endian {
        Endian::Little => u32_le,
        Endian::Big => u32_be,
    };
    let read_u64: ReadU64 = match endian {
        Endian::Little => u64_le,
        Endian::Big => u64_be,
    };
    let cputype: u32 = read_u32(slice, 4)?;
    let _cpusubtype: u32 = read_u32(slice, 8)?;
    let filetype: u32 = read_u32(slice, 12)?;
    let ncmds: u32 = read_u32(slice, 16)?;
    let sizeofcmds: u32 = read_u32(slice, 20)?;
    let flags: u32 = read_u32(slice, 24)?;

    let header_size: usize = match bitness {
        Bitness::Bits32 => MACH_HEADER_32_SIZE,
        Bitness::Bits64 => MACH_HEADER_64_SIZE,
    };
    let header: SliceHeader = SliceHeader {
        cpu: CpuKind::from_cputype(cputype),
        bitness,
        endian,
        ncmds,
        sizeofcmds,
        filetype,
        flags,
    };

    let mut segments: Vec<Segment> = Vec::new();
    let mut load_commands: Vec<LoadCommand> = Vec::with_capacity(ncmds as usize);
    let mut encryption: Option<EncryptionInfo> = None;
    let mut code_signature_off: Option<u32> = None;
    let mut code_signature_size: Option<u32> = None;
    let mut cursor: usize = header_size;

    for idx in 0..ncmds {
        if cursor + 8 > slice.len() {
            return Err(Error::LoadCommand(
                idx as usize,
                "cmd header truncated".to_owned(),
            ));
        }
        let cmd_raw: u32 = read_u32(slice, cursor)?;
        let cmd: u32 = cmd_raw & !LC_REQ_DYLD;
        let cmdsize: u32 = read_u32(slice, cursor + 4)?;
        let cmdsize_usize: usize = cmdsize as usize;
        if cmdsize < 8 || cursor + cmdsize_usize > slice.len() {
            return Err(Error::LoadCommand(
                idx as usize,
                format!("cmdsize {cmdsize} out of range"),
            ));
        }
        load_commands.push(LoadCommand {
            cmd,
            cmdsize,
            data_offset: cursor,
        });

        match cmd {
            LC_SEGMENT_64 if matches!(bitness, Bitness::Bits64) => {
                let segment: Segment = parse_segment_64(slice, cursor, read_u32, read_u64, idx)?;
                segments.push(segment);
            }
            LC_SEGMENT if matches!(bitness, Bitness::Bits32) => {
                let segment: Segment = parse_segment_32(slice, cursor, read_u32, idx)?;
                segments.push(segment);
            }
            LC_ENCRYPTION_INFO_64 | LC_ENCRYPTION_INFO => {
                let crypt_off: u32 = read_u32(slice, cursor + 8)?;
                let crypt_size: u32 = read_u32(slice, cursor + 12)?;
                let crypt_id: u32 = read_u32(slice, cursor + 16)?;
                encryption = Some(EncryptionInfo {
                    crypt_off,
                    crypt_size,
                    crypt_id,
                });
            }
            LC_CODE_SIGNATURE => {
                let off: u32 = read_u32(slice, cursor + 8)?;
                let size: u32 = read_u32(slice, cursor + 12)?;
                code_signature_off = Some(off);
                code_signature_size = Some(size);
            }
            _ => {}
        }
        cursor += cmdsize_usize;
    }

    Ok(ParsedSlice {
        header,
        segments,
        load_commands,
        encryption,
        code_signature_off,
        code_signature_size,
    })
}

#[must_use]
pub fn find_section<'a>(parsed: &'a ParsedSlice, seg: &str, sect: &str) -> Option<&'a Section> {
    for segment in &parsed.segments {
        for s in &segment.sections {
            if s.seg == seg && s.name == sect {
                return Some(s);
            }
        }
    }
    None
}

#[must_use]
pub fn section_bytes<'a>(slice: &'a [u8], section: &Section) -> Option<&'a [u8]> {
    let start: usize = section.offset as usize;
    let len: usize = usize::try_from(section.size).ok()?;
    let end: usize = start.checked_add(len)?;
    slice.get(start..end)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn cpu_kind_recognizes_arm64() {
        assert_eq!(CpuKind::from_cputype(0x0100_000C), CpuKind::Arm64);
        assert_eq!(CpuKind::from_cputype(0x0100_0007), CpuKind::X86_64);
    }

    #[test]
    fn detect_magic_recognizes_fat() {
        let mut bytes: [u8; 8] = [0u8; 8];
        bytes[..4].copy_from_slice(&FAT_MAGIC_BE.to_be_bytes());
        assert_eq!(detect_magic(&bytes), Some(MachoKind::Fat32));
    }

    #[test]
    fn detect_magic_recognizes_slice64_le() {
        let mut bytes: [u8; 4] = [0u8; 4];
        bytes.copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        assert_eq!(detect_magic(&bytes), Some(MachoKind::Slice64Le));
    }
}
