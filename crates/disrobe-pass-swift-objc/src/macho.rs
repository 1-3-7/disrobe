use disrobe_bytes::read_uleb128_at;
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
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_DYSYMTAB: u32 = 0xB;
pub const LC_LOAD_DYLIB: u32 = 0xC;
pub const LC_ID_DYLIB: u32 = 0xD;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18;
pub const LC_UUID: u32 = 0x1B;
pub const LC_RPATH: u32 = 0x1C;
pub const LC_REEXPORT_DYLIB: u32 = 0x1F;
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x23;
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_MAIN: u32 = 0x28;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_SOURCE_VERSION: u32 = 0x2A;
pub const LC_VERSION_MIN_TVOS: u32 = 0x2F;
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
pub const LC_BUILD_VERSION: u32 = 0x32;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2C;
pub const LC_CODE_SIGNATURE: u32 = 0x1D;
pub const LC_REQ_DYLD: u32 = 0x8000_0000;

pub const S_SYMBOL_STUBS: u32 = 0x8;
pub const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
pub const SECTION_TYPE_MASK: u32 = 0xFF;

pub const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;
pub const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;

const MAX_DYLIBS: usize = 4096;
const MAX_RPATHS: usize = 1024;
const MAX_INDIRECT_SYMBOLS: usize = 1 << 22;

const NLIST_64_SIZE: usize = 16;
const NLIST_32_SIZE: usize = 12;
const MAX_SYMBOLS: usize = 1 << 22;
const MAX_SYMBOL_LEN: usize = 4096;
const FAT_ARCH_COUNT_CAP: usize = 4096;

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
    pub reserved1: u32,
    pub reserved2: u32,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedRegion {
    pub file_off: u64,
    pub size: u64,
    pub crypt_id: u32,
}

impl EncryptedRegion {
    #[must_use]
    pub const fn end(self) -> u64 {
        self.file_off.saturating_add(self.size)
    }

    #[must_use]
    pub const fn overlaps(self, off: u64, len: u64) -> bool {
        off < self.end() && self.file_off < off.saturating_add(len)
    }
}

#[must_use]
pub fn encrypted_region(parsed: &ParsedSlice) -> Option<EncryptedRegion> {
    let info: &EncryptionInfo = parsed.encryption.as_ref()?;
    if info.crypt_id == 0 || info.crypt_size == 0 {
        return None;
    }
    Some(EncryptedRegion {
        file_off: u64::from(info.crypt_off),
        size: u64::from(info.crypt_size),
        crypt_id: info.crypt_id,
    })
}

#[must_use]
pub fn section_is_encrypted_at_rest(parsed: &ParsedSlice, section: &Section) -> bool {
    encrypted_region(parsed).is_some_and(|region: EncryptedRegion| {
        region.overlaps(u64::from(section.offset), section.size)
    })
}

#[must_use]
pub fn readable_section_bytes<'a>(
    slice: &'a [u8],
    parsed: &ParsedSlice,
    section: &Section,
) -> Option<&'a [u8]> {
    if section_is_encrypted_at_rest(parsed, section) {
        return None;
    }
    section_bytes(slice, section)
}

const MAX_FUNCTION_STARTS: usize = 1 << 22;
const MAX_EXPORT_NODES: usize = 1 << 20;
const MAX_EXPORT_DEPTH: usize = 128;
const MAX_EXPORT_NAME: usize = 4096;

const EXPORT_SYMBOL_FLAGS_KIND_MASK: u64 = 0x03;
const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

#[must_use]
pub fn function_starts(slice: &[u8], parsed: &ParsedSlice) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    let Some(location): Option<&LinkeditData> = parsed.function_starts.as_ref() else {
        return out;
    };
    let Some(data): Option<&[u8]> = linkedit_bytes(slice, *location) else {
        return out;
    };
    let Some(base): Option<u64> = image_base(parsed) else {
        return out;
    };
    let mut address: u64 = base;
    let mut cursor: usize = 0;
    while cursor < data.len() && out.len() < MAX_FUNCTION_STARTS {
        let Ok((delta, consumed)): core::result::Result<(u64, usize), _> =
            read_uleb128_at(data, cursor)
        else {
            break;
        };
        if consumed == 0 || delta == 0 {
            break;
        }
        cursor = cursor.saturating_add(consumed);
        address = address.wrapping_add(delta);
        out.push(address);
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportKind {
    Regular,
    ThreadLocal,
    Absolute,
    Reexport,
    StubAndResolver,
}

impl ExportKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Regular => "regular",
            Self::ThreadLocal => "thread-local",
            Self::Absolute => "absolute",
            Self::Reexport => "reexport",
            Self::StubAndResolver => "stub-and-resolver",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedSymbol {
    pub name: String,
    pub kind: ExportKind,
    pub address: Option<u64>,
    pub reexport_from_dylib_ordinal: Option<u64>,
    pub reexport_name: Option<String>,
}

#[must_use]
pub fn exported_symbols(slice: &[u8], parsed: &ParsedSlice) -> Vec<ExportedSymbol> {
    let mut out: Vec<ExportedSymbol> = Vec::new();
    let Some(location): Option<&LinkeditData> = parsed
        .exports_trie
        .as_ref()
        .or(parsed.dyld_info_exports.as_ref())
    else {
        return out;
    };
    let Some(data): Option<&[u8]> = linkedit_bytes(slice, *location) else {
        return out;
    };
    let base: u64 = image_base(parsed).unwrap_or(0);
    let mut visited: usize = 0;
    walk_export_node(data, 0, &mut String::new(), base, 0, &mut visited, &mut out);
    out.sort_by(|a: &ExportedSymbol, b: &ExportedSymbol| a.name.cmp(&b.name));
    out.dedup_by(|a: &mut ExportedSymbol, b: &mut ExportedSymbol| a.name == b.name);
    out
}

fn linkedit_bytes(slice: &[u8], location: LinkeditData) -> Option<&[u8]> {
    let start: usize = location.offset as usize;
    let size: usize = usize::try_from(location.size).ok()?;
    if size == 0 {
        return None;
    }
    slice.get(start..start.checked_add(size)?)
}

fn walk_export_node(
    data: &[u8],
    node_off: usize,
    prefix: &mut String,
    base: u64,
    depth: usize,
    visited: &mut usize,
    out: &mut Vec<ExportedSymbol>,
) {
    if depth > MAX_EXPORT_DEPTH || *visited >= MAX_EXPORT_NODES || node_off >= data.len() {
        return;
    }
    *visited += 1;
    let Ok((terminal_size, mut cursor)): core::result::Result<(u64, usize), _> =
        read_uleb128_at(data, node_off)
            .map(|(value, consumed): (u64, usize)| (value, node_off.saturating_add(consumed)))
    else {
        return;
    };
    if terminal_size > 0 {
        if let Some(symbol) = read_export_terminal(data, cursor, prefix, base) {
            out.push(symbol);
        }
        let Some(after): Option<usize> = usize::try_from(terminal_size)
            .ok()
            .and_then(|size: usize| cursor.checked_add(size))
        else {
            return;
        };
        cursor = after;
    }
    let Some(&child_count): Option<&u8> = data.get(cursor) else {
        return;
    };
    cursor = cursor.saturating_add(1);
    for _ in 0..child_count {
        let Some(edge): Option<&str> = cstr_in(data, cursor, MAX_EXPORT_NAME) else {
            return;
        };
        cursor = cursor.saturating_add(edge.len()).saturating_add(1);
        let Ok((child_off, consumed)): core::result::Result<(u64, usize), _> =
            read_uleb128_at(data, cursor)
        else {
            return;
        };
        cursor = cursor.saturating_add(consumed);
        if prefix.len().saturating_add(edge.len()) > MAX_EXPORT_NAME {
            continue;
        }
        let restore: usize = prefix.len();
        prefix.push_str(edge);
        if let Ok(child) = usize::try_from(child_off)
            && child != node_off
        {
            walk_export_node(data, child, prefix, base, depth + 1, visited, out);
        }
        prefix.truncate(restore);
    }
}

fn read_export_terminal(data: &[u8], at: usize, name: &str, base: u64) -> Option<ExportedSymbol> {
    if name.is_empty() {
        return None;
    }
    let (flags, consumed): (u64, usize) = read_uleb128_at(data, at).ok()?;
    let mut cursor: usize = at.checked_add(consumed)?;
    if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
        let (ordinal, used): (u64, usize) = read_uleb128_at(data, cursor).ok()?;
        cursor = cursor.checked_add(used)?;
        let imported: &str = cstr_in(data, cursor, MAX_EXPORT_NAME)?;
        return Some(ExportedSymbol {
            name: name.to_owned(),
            kind: ExportKind::Reexport,
            address: None,
            reexport_from_dylib_ordinal: Some(ordinal),
            reexport_name: (!imported.is_empty()).then(|| imported.to_owned()),
        });
    }
    if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
        let (stub, used): (u64, usize) = read_uleb128_at(data, cursor).ok()?;
        return Some(ExportedSymbol {
            name: name.to_owned(),
            kind: ExportKind::StubAndResolver,
            address: Some(base.wrapping_add(stub)),
            reexport_from_dylib_ordinal: None,
            reexport_name: None,
        })
        .filter(|_| cursor.checked_add(used).is_some());
    }
    let (offset, _): (u64, usize) = read_uleb128_at(data, cursor).ok()?;
    let kind: ExportKind = match flags & EXPORT_SYMBOL_FLAGS_KIND_MASK {
        1 => ExportKind::ThreadLocal,
        2 => ExportKind::Absolute,
        _ => ExportKind::Regular,
    };
    let address: u64 = match kind {
        ExportKind::Absolute => offset,
        _ => base.wrapping_add(offset),
    };
    Some(ExportedSymbol {
        name: name.to_owned(),
        kind,
        address: Some(address),
        reexport_from_dylib_ordinal: None,
        reexport_name: None,
    })
}

fn cstr_in(data: &[u8], at: usize, max_len: usize) -> Option<&str> {
    let end: usize = at.checked_add(max_len)?.min(data.len());
    let window: &[u8] = data.get(at..end)?;
    let nul: usize = window.iter().position(|byte: &u8| *byte == 0)?;
    std::str::from_utf8(&window[..nul]).ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DylibKind {
    Load,
    LoadWeak,
    Reexport,
    LazyLoad,
    LoadUpward,
    Id,
}

impl DylibKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Load => "load",
            Self::LoadWeak => "load-weak",
            Self::Reexport => "reexport",
            Self::LazyLoad => "lazy-load",
            Self::LoadUpward => "load-upward",
            Self::Id => "id",
        }
    }

    const fn from_cmd(cmd: u32) -> Option<Self> {
        match cmd {
            LC_LOAD_DYLIB => Some(Self::Load),
            LC_LOAD_WEAK_DYLIB => Some(Self::LoadWeak),
            LC_REEXPORT_DYLIB => Some(Self::Reexport),
            LC_LAZY_LOAD_DYLIB => Some(Self::LazyLoad),
            LC_LOAD_UPWARD_DYLIB => Some(Self::LoadUpward),
            LC_ID_DYLIB => Some(Self::Id),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DylibReference {
    pub kind: DylibKind,
    pub name: String,
    pub current_version: String,
    pub compatibility_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformVersion {
    pub platform: u32,
    pub min_os: PackedVersion,
    pub sdk: PackedVersion,
}

impl PlatformVersion {
    #[must_use]
    pub const fn platform_label(self) -> &'static str {
        match self.platform {
            1 => "macos",
            2 => "ios",
            3 => "tvos",
            4 => "watchos",
            5 => "bridgeos",
            6 => "mac-catalyst",
            7 => "ios-simulator",
            8 => "tvos-simulator",
            9 => "watchos-simulator",
            10 => "driverkit",
            11 => "visionos",
            12 => "visionos-simulator",
            _ => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackedVersion(pub u32);

impl PackedVersion {
    #[must_use]
    pub const fn major(self) -> u32 {
        self.0 >> 16
    }

    #[must_use]
    pub const fn minor(self) -> u32 {
        (self.0 >> 8) & 0xFF
    }

    #[must_use]
    pub const fn patch(self) -> u32 {
        self.0 & 0xFF
    }
}

impl core::fmt::Display for PackedVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}", self.major(), self.minor(), self.patch())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryPoint {
    pub entry_offset: u64,
    pub stack_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkeditData {
    pub offset: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DysymtabInfo {
    pub local_sym_index: u32,
    pub local_sym_count: u32,
    pub extdef_sym_index: u32,
    pub extdef_sym_count: u32,
    pub undef_sym_index: u32,
    pub undef_sym_count: u32,
    pub indirect_sym_off: u32,
    pub indirect_sym_count: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SymtabInfo {
    pub sym_off: u32,
    pub num_syms: u32,
    pub str_off: u32,
    pub str_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedSlice {
    pub header: SliceHeader,
    pub segments: Vec<Segment>,
    pub load_commands: Vec<LoadCommand>,
    pub encryption: Option<EncryptionInfo>,
    pub code_signature_off: Option<u32>,
    pub code_signature_size: Option<u32>,
    pub symtab: Option<SymtabInfo>,
    pub dysymtab: Option<DysymtabInfo>,
    pub uuid: Option<String>,
    pub id_dylib: Option<DylibReference>,
    pub dylibs: Vec<DylibReference>,
    pub rpaths: Vec<String>,
    pub platform_version: Option<PlatformVersion>,
    pub entry_point: Option<EntryPoint>,
    pub source_version: Option<u64>,
    pub function_starts: Option<LinkeditData>,
    pub data_in_code: Option<LinkeditData>,
    pub chained_fixups: Option<LinkeditData>,
    pub exports_trie: Option<LinkeditData>,
    pub dyld_info_exports: Option<LinkeditData>,
}

impl Default for ParsedSlice {
    fn default() -> Self {
        Self {
            header: SliceHeader {
                cpu: CpuKind::Unknown(0),
                bitness: Bitness::Bits64,
                endian: Endian::Little,
                ncmds: 0,
                sizeofcmds: 0,
                filetype: 0,
                flags: 0,
            },
            segments: Vec::new(),
            load_commands: Vec::new(),
            encryption: None,
            code_signature_off: None,
            code_signature_size: None,
            symtab: None,
            dysymtab: None,
            uuid: None,
            id_dylib: None,
            dylibs: Vec::new(),
            rpaths: Vec::new(),
            platform_version: None,
            entry_point: None,
            source_version: None,
            function_starts: None,
            data_in_code: None,
            chained_fixups: None,
            exports_trie: None,
            dyld_info_exports: None,
        }
    }
}

#[inline]
pub(crate) fn u32_le(bytes: &[u8], off: usize) -> Result<u32> {
    let end: usize = off.checked_add(4).ok_or(Error::Truncated(off))?;
    let slice: &[u8] = bytes.get(off..end).ok_or(Error::Truncated(off))?;
    let arr: [u8; 4] = [slice[0], slice[1], slice[2], slice[3]];
    Ok(u32::from_le_bytes(arr))
}

#[inline]
fn u32_be(bytes: &[u8], off: usize) -> Result<u32> {
    let end: usize = off.checked_add(4).ok_or(Error::Truncated(off))?;
    let slice: &[u8] = bytes.get(off..end).ok_or(Error::Truncated(off))?;
    let arr: [u8; 4] = [slice[0], slice[1], slice[2], slice[3]];
    Ok(u32::from_be_bytes(arr))
}

#[inline]
pub(crate) fn u64_le(bytes: &[u8], off: usize) -> Result<u64> {
    let end: usize = off.checked_add(8).ok_or(Error::Truncated(off))?;
    let slice: &[u8] = bytes.get(off..end).ok_or(Error::Truncated(off))?;
    let mut arr: [u8; 8] = [0u8; 8];
    arr.copy_from_slice(slice);
    Ok(u64::from_le_bytes(arr))
}

#[inline]
fn u64_be(bytes: &[u8], off: usize) -> Result<u64> {
    let end: usize = off.checked_add(8).ok_or(Error::Truncated(off))?;
    let slice: &[u8] = bytes.get(off..end).ok_or(Error::Truncated(off))?;
    let mut arr: [u8; 8] = [0u8; 8];
    arr.copy_from_slice(slice);
    Ok(u64::from_be_bytes(arr))
}

#[inline]
fn read_cstr16(bytes: &[u8], off: usize) -> Result<String> {
    let end: usize = off.checked_add(16).ok_or(Error::Truncated(off))?;
    let raw: &[u8] = bytes.get(off..end).ok_or(Error::Truncated(off))?;
    let stop: usize = raw.iter().position(|b: &u8| *b == 0).unwrap_or(raw.len());
    Ok(String::from_utf8_lossy(&raw[..stop]).into_owned())
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
    let available: usize = bytes.len().saturating_sub(8);
    let nfat_usize: usize = usize::try_from(nfat)
        .map_err(|_| Error::BadFatHeader(format!("fat arch count {nfat} is not addressable")))?;
    if nfat_usize > FAT_ARCH_COUNT_CAP {
        return Err(Error::BadFatHeader(format!(
            "fat arch count {nfat} exceeds the {FAT_ARCH_COUNT_CAP} arch cap"
        )));
    }
    let table_bytes: usize = nfat_usize
        .checked_mul(entry_size)
        .ok_or_else(|| Error::BadFatHeader("fat arch table size overflows".to_owned()))?;
    if table_bytes > available {
        return Err(Error::BadFatHeader(format!(
            "fat arch count {nfat} exceeds {available} table bytes"
        )));
    }
    let mut out: Vec<FatArchEntry> = Vec::with_capacity(nfat_usize);
    let mut cursor: usize = 8;
    for _ in 0..nfat_usize {
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
    let max_sections: usize = slice.len() / SECTION_64_SIZE;
    let mut sections: Vec<Section> = Vec::with_capacity((nsects as usize).min(max_sections));
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
        let reserved1: u32 = read_u32(slice, s_off + 68)?;
        let reserved2: u32 = read_u32(slice, s_off + 72)?;
        sections.push(Section {
            seg: seg_field,
            name: sect_name,
            addr,
            size,
            offset,
            flags: sflags,
            reserved1,
            reserved2,
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
    let max_sections: usize = slice.len() / SECTION_32_SIZE;
    let mut sections: Vec<Section> = Vec::with_capacity((nsects as usize).min(max_sections));
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
        let reserved1: u32 = read_u32(slice, s_off + 60)?;
        let reserved2: u32 = read_u32(slice, s_off + 64)?;
        sections.push(Section {
            seg: seg_field,
            name: sect_name,
            addr: u64::from(addr),
            size: u64::from(size),
            offset,
            flags: sflags,
            reserved1,
            reserved2,
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
    let max_commands: usize = slice.len() / 8;
    let mut load_commands: Vec<LoadCommand> =
        Vec::with_capacity((ncmds as usize).min(max_commands));
    let mut encryption: Option<EncryptionInfo> = None;
    let mut code_signature_off: Option<u32> = None;
    let mut code_signature_size: Option<u32> = None;
    let mut symtab: Option<SymtabInfo> = None;
    let mut dysymtab: Option<DysymtabInfo> = None;
    let mut uuid: Option<String> = None;
    let mut id_dylib: Option<DylibReference> = None;
    let mut dylibs: Vec<DylibReference> = Vec::new();
    let mut rpaths: Vec<String> = Vec::new();
    let mut platform_version: Option<PlatformVersion> = None;
    let mut entry_point: Option<EntryPoint> = None;
    let mut source_version: Option<u64> = None;
    let mut function_starts: Option<LinkeditData> = None;
    let mut data_in_code: Option<LinkeditData> = None;
    let mut chained_fixups: Option<LinkeditData> = None;
    let mut exports_trie: Option<LinkeditData> = None;
    let mut dyld_info_exports: Option<LinkeditData> = None;
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
            LC_SYMTAB => {
                let sym_off: u32 = read_u32(slice, cursor + 8)?;
                let num_syms: u32 = read_u32(slice, cursor + 12)?;
                let str_off: u32 = read_u32(slice, cursor + 16)?;
                let str_size: u32 = read_u32(slice, cursor + 20)?;
                symtab = Some(SymtabInfo {
                    sym_off,
                    num_syms,
                    str_off,
                    str_size,
                });
            }
            LC_DYSYMTAB => {
                dysymtab = Some(DysymtabInfo {
                    local_sym_index: read_u32(slice, cursor + 8)?,
                    local_sym_count: read_u32(slice, cursor + 12)?,
                    extdef_sym_index: read_u32(slice, cursor + 16)?,
                    extdef_sym_count: read_u32(slice, cursor + 20)?,
                    undef_sym_index: read_u32(slice, cursor + 24)?,
                    undef_sym_count: read_u32(slice, cursor + 28)?,
                    indirect_sym_off: read_u32(slice, cursor + 56)?,
                    indirect_sym_count: read_u32(slice, cursor + 60)?,
                });
            }
            LC_UUID => {
                let raw: &[u8] = slice
                    .get(cursor + 8..cursor + 24)
                    .ok_or_else(|| Error::LoadCommand(idx as usize, "uuid truncated".to_owned()))?;
                uuid = Some(format_uuid(raw));
            }
            LC_RPATH => {
                if rpaths.len() < MAX_RPATHS
                    && let Some(path) = lc_string(slice, cursor, cmdsize_usize, read_u32)
                {
                    rpaths.push(path);
                }
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
            | LC_LOAD_UPWARD_DYLIB | LC_ID_DYLIB => {
                if let Some(kind) = DylibKind::from_cmd(cmd)
                    && let Some(name) = lc_string(slice, cursor, cmdsize_usize, read_u32)
                {
                    let current: u32 = read_u32(slice, cursor + 16).unwrap_or(0);
                    let compat: u32 = read_u32(slice, cursor + 20).unwrap_or(0);
                    let reference: DylibReference = DylibReference {
                        kind,
                        name,
                        current_version: PackedVersion(current).to_string(),
                        compatibility_version: PackedVersion(compat).to_string(),
                    };
                    if kind == DylibKind::Id {
                        id_dylib = Some(reference);
                    } else if dylibs.len() < MAX_DYLIBS {
                        dylibs.push(reference);
                    }
                }
            }
            LC_BUILD_VERSION => {
                platform_version = Some(PlatformVersion {
                    platform: read_u32(slice, cursor + 8)?,
                    min_os: PackedVersion(read_u32(slice, cursor + 12)?),
                    sdk: PackedVersion(read_u32(slice, cursor + 16)?),
                });
            }
            LC_VERSION_MIN_MACOSX
            | LC_VERSION_MIN_IPHONEOS
            | LC_VERSION_MIN_TVOS
            | LC_VERSION_MIN_WATCHOS
                if platform_version.is_none() =>
            {
                let platform: u32 = match cmd {
                    LC_VERSION_MIN_MACOSX => 1,
                    LC_VERSION_MIN_IPHONEOS => 2,
                    LC_VERSION_MIN_TVOS => 3,
                    _ => 4,
                };
                platform_version = Some(PlatformVersion {
                    platform,
                    min_os: PackedVersion(read_u32(slice, cursor + 8)?),
                    sdk: PackedVersion(read_u32(slice, cursor + 12)?),
                });
            }
            LC_MAIN => {
                entry_point = Some(EntryPoint {
                    entry_offset: read_u64(slice, cursor + 8)?,
                    stack_size: read_u64(slice, cursor + 16)?,
                });
            }
            LC_SOURCE_VERSION => {
                source_version = Some(read_u64(slice, cursor + 8)?);
            }
            LC_FUNCTION_STARTS => {
                function_starts = Some(read_linkedit(slice, cursor, read_u32)?);
            }
            LC_DATA_IN_CODE => {
                data_in_code = Some(read_linkedit(slice, cursor, read_u32)?);
            }
            LC_DYLD_CHAINED_FIXUPS => {
                chained_fixups = Some(read_linkedit(slice, cursor, read_u32)?);
            }
            LC_DYLD_EXPORTS_TRIE => {
                exports_trie = Some(read_linkedit(slice, cursor, read_u32)?);
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                dyld_info_exports = Some(LinkeditData {
                    offset: read_u32(slice, cursor + 40)?,
                    size: read_u32(slice, cursor + 44)?,
                });
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
        symtab,
        dysymtab,
        uuid,
        id_dylib,
        dylibs,
        rpaths,
        platform_version,
        entry_point,
        source_version,
        function_starts,
        data_in_code,
        chained_fixups,
        exports_trie,
        dyld_info_exports,
    })
}

fn format_uuid(raw: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out: String = String::with_capacity(36);
    for (index, byte) in raw.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        let _: core::result::Result<(), core::fmt::Error> = write!(out, "{byte:02x}");
    }
    out
}

fn read_linkedit(slice: &[u8], cursor: usize, read_u32: ReadU32) -> Result<LinkeditData> {
    Ok(LinkeditData {
        offset: read_u32(slice, cursor + 8)?,
        size: read_u32(slice, cursor + 12)?,
    })
}

fn lc_string(slice: &[u8], cursor: usize, cmdsize: usize, read_u32: ReadU32) -> Option<String> {
    let name_off: u32 = read_u32(slice, cursor + 8).ok()?;
    let start: usize = cursor.checked_add(usize::try_from(name_off).ok()?)?;
    let end: usize = cursor.checked_add(cmdsize)?;
    if start >= end {
        return None;
    }
    let window: &[u8] = slice.get(start..end.min(slice.len()))?;
    let stop: usize = window
        .iter()
        .position(|b: &u8| *b == 0)
        .unwrap_or(window.len());
    std::str::from_utf8(&window[..stop])
        .ok()
        .map(str::to_owned)
        .filter(|s: &String| !s.is_empty())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportThunk {
    pub address: u64,
    pub section: String,
    pub segment: String,
    pub slot_index: u32,
    pub symbol_index: u32,
    pub name: Option<String>,
}

#[must_use]
pub fn import_thunks(slice: &[u8], parsed: &ParsedSlice) -> Vec<ImportThunk> {
    let (Some(dysymtab), Some(symtab)): (Option<DysymtabInfo>, Option<SymtabInfo>) =
        (parsed.dysymtab, parsed.symtab)
    else {
        return Vec::new();
    };
    if dysymtab.indirect_sym_count == 0 {
        return Vec::new();
    }
    let read_u32: ReadU32 = match parsed.header.endian {
        Endian::Little => u32_le,
        Endian::Big => u32_be,
    };
    let entry_size: usize = match parsed.header.bitness {
        Bitness::Bits64 => NLIST_64_SIZE,
        Bitness::Bits32 => NLIST_32_SIZE,
    };
    let indirect_base: usize = dysymtab.indirect_sym_off as usize;
    let indirect_count: usize = (dysymtab.indirect_sym_count as usize).min(MAX_INDIRECT_SYMBOLS);
    let str_base: usize = symtab.str_off as usize;
    let str_end: usize = str_base.saturating_add(symtab.str_size as usize);
    let mut out: Vec<ImportThunk> = Vec::new();

    for segment in &parsed.segments {
        for section in &segment.sections {
            let section_type: u32 = section.flags & SECTION_TYPE_MASK;
            let stride: u64 = match section_type {
                S_SYMBOL_STUBS => u64::from(section.reserved2),
                S_LAZY_SYMBOL_POINTERS | S_NON_LAZY_SYMBOL_POINTERS => {
                    match parsed.header.bitness {
                        Bitness::Bits64 => 8,
                        Bitness::Bits32 => 4,
                    }
                }
                _ => continue,
            };
            if stride == 0 {
                continue;
            }
            let slot_count: u64 = section.size / stride;
            for slot in 0..slot_count {
                let Ok(slot_u32): core::result::Result<u32, _> = u32::try_from(slot) else {
                    break;
                };
                let table_index: usize = match usize::try_from(slot)
                    .ok()
                    .and_then(|s: usize| s.checked_add(section.reserved1 as usize))
                {
                    Some(index) if index < indirect_count => index,
                    _ => break,
                };
                let Some(entry_off): Option<usize> = table_index
                    .checked_mul(4)
                    .and_then(|delta: usize| indirect_base.checked_add(delta))
                else {
                    break;
                };
                let Ok(symbol_index): Result<u32> = read_u32(slice, entry_off) else {
                    break;
                };
                let name: Option<String> = if symbol_index & INDIRECT_SYMBOL_ABS != 0
                    || symbol_index & INDIRECT_SYMBOL_LOCAL != 0
                    || symbol_index >= symtab.num_syms
                {
                    None
                } else {
                    (symbol_index as usize)
                        .checked_mul(entry_size)
                        .and_then(|delta: usize| (symtab.sym_off as usize).checked_add(delta))
                        .and_then(|off: usize| read_u32(slice, off).ok())
                        .filter(|strx: &u32| *strx != 0)
                        .and_then(|strx: u32| str_base.checked_add(strx as usize))
                        .filter(|name_off: &usize| *name_off < str_end)
                        .and_then(|name_off: usize| {
                            read_cstr_bounded(slice, name_off, str_end.min(slice.len()))
                        })
                };
                out.push(ImportThunk {
                    address: section.addr.saturating_add(slot.saturating_mul(stride)),
                    section: section.name.clone(),
                    segment: section.seg.clone(),
                    slot_index: slot_u32,
                    symbol_index,
                    name,
                });
            }
        }
    }
    out
}

#[must_use]
pub fn symbol_names(slice: &[u8], parsed: &ParsedSlice) -> Vec<String> {
    let Some(symtab): Option<SymtabInfo> = parsed.symtab else {
        return Vec::new();
    };
    let entry_size: usize = match parsed.header.bitness {
        Bitness::Bits64 => NLIST_64_SIZE,
        Bitness::Bits32 => NLIST_32_SIZE,
    };
    let read_u32: ReadU32 = match parsed.header.endian {
        Endian::Little => u32_le,
        Endian::Big => u32_be,
    };
    let sym_base: usize = symtab.sym_off as usize;
    let str_base: usize = symtab.str_off as usize;
    let str_end: usize = str_base.saturating_add(symtab.str_size as usize);
    let count: usize = (symtab.num_syms as usize).min(MAX_SYMBOLS);
    let mut out: Vec<String> = Vec::with_capacity(count);
    for i in 0..count {
        let Some(entry_off): Option<usize> = i
            .checked_mul(entry_size)
            .and_then(|delta: usize| sym_base.checked_add(delta))
        else {
            break;
        };
        let Ok(n_strx): Result<u32> = read_u32(slice, entry_off) else {
            break;
        };
        let name_off: usize = str_base.saturating_add(n_strx as usize);
        if name_off >= str_end {
            continue;
        }
        if let Some(name) = read_cstr_bounded(slice, name_off, str_end.min(slice.len()))
            && !name.is_empty()
        {
            out.push(name);
        }
    }
    out
}

pub(crate) fn read_cstr_bounded(slice: &[u8], start: usize, hard_end: usize) -> Option<String> {
    let cap: usize = start.checked_add(MAX_SYMBOL_LEN)?.min(hard_end);
    let window: &[u8] = slice.get(start..cap)?;
    let nul: usize = window.iter().position(|b: &u8| *b == 0)?;
    std::str::from_utf8(&window[..nul]).ok().map(str::to_owned)
}

const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_SECT: u8 = 0x0e;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSymbol {
    pub name: String,
    pub address: u64,
    pub section_index: u8,
}

#[must_use]
pub fn function_symbols(slice: &[u8], parsed: &ParsedSlice) -> Vec<FunctionSymbol> {
    let Some(symtab): Option<SymtabInfo> = parsed.symtab else {
        return Vec::new();
    };
    let text_sections: Vec<u8> = text_section_indices(parsed);
    if text_sections.is_empty() {
        return Vec::new();
    }
    let is_64: bool = matches!(parsed.header.bitness, Bitness::Bits64);
    let entry_size: usize = if is_64 { NLIST_64_SIZE } else { NLIST_32_SIZE };
    let read_u32: ReadU32 = match parsed.header.endian {
        Endian::Little => u32_le,
        Endian::Big => u32_be,
    };
    let sym_base: usize = symtab.sym_off as usize;
    let str_base: usize = symtab.str_off as usize;
    let str_end: usize = str_base.saturating_add(symtab.str_size as usize);
    let count: usize = (symtab.num_syms as usize).min(MAX_SYMBOLS);
    let mut out: Vec<FunctionSymbol> = Vec::new();
    for i in 0..count {
        let Some(entry_off): Option<usize> = i
            .checked_mul(entry_size)
            .and_then(|delta: usize| sym_base.checked_add(delta))
        else {
            break;
        };
        let Ok(n_strx): Result<u32> = read_u32(slice, entry_off) else {
            break;
        };
        let Some(&n_type): Option<&u8> = slice.get(entry_off + 4) else {
            break;
        };
        let Some(&n_sect): Option<&u8> = slice.get(entry_off + 5) else {
            break;
        };
        if n_type & N_STAB != 0 || n_type & N_TYPE != N_SECT || n_sect == 0 {
            continue;
        }
        if !text_sections.contains(&n_sect) {
            continue;
        }
        let value_off: usize = entry_off + 8;
        let address: u64 = if is_64 {
            let read_u64: ReadU64 = match parsed.header.endian {
                Endian::Little => u64_le,
                Endian::Big => u64_be,
            };
            let Ok(v): Result<u64> = read_u64(slice, value_off) else {
                continue;
            };
            v
        } else {
            let Ok(v): Result<u32> = read_u32(slice, value_off) else {
                continue;
            };
            u64::from(v)
        };
        if address == 0 {
            continue;
        }
        let name_off: usize = str_base.saturating_add(n_strx as usize);
        if n_strx == 0 || name_off >= str_end {
            continue;
        }
        if let Some(name) = read_cstr_bounded(slice, name_off, str_end.min(slice.len()))
            && !name.is_empty()
        {
            out.push(FunctionSymbol {
                name,
                address,
                section_index: n_sect,
            });
        }
    }
    out
}

const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

fn text_section_indices(parsed: &ParsedSlice) -> Vec<u8> {
    let mut indices: Vec<u8> = Vec::new();
    let mut running: u32 = 0;
    for seg in &parsed.segments {
        for sect in &seg.sections {
            running = running.saturating_add(1);
            let has_instr_attr: bool =
                sect.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0;
            let is_code: bool = has_instr_attr || (sect.seg == "__TEXT" && sect.name == "__text");
            if is_code && let Ok(idx) = u8::try_from(running) {
                indices.push(idx);
            }
        }
    }
    indices
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

pub const CHAINED_PTR_TARGET_MASK: u64 = 0x0000_000F_FFFF_FFFF;
pub const FAST_DATA_MASK: u64 = 0x0000_7fff_ffff_fff8;

#[must_use]
pub fn image_base(parsed: &ParsedSlice) -> Option<u64> {
    parsed
        .segments
        .iter()
        .filter(|seg: &&Segment| seg.name != "__PAGEZERO" && seg.vmsize > 0)
        .map(|seg: &Segment| seg.vmaddr)
        .min()
}

#[must_use]
pub fn vmaddr_to_offset(parsed: &ParsedSlice, vmaddr: u64) -> Option<usize> {
    for seg in &parsed.segments {
        if seg.name == "__PAGEZERO" {
            continue;
        }
        let seg_end: u64 = seg.vmaddr.checked_add(seg.filesize)?;
        if vmaddr >= seg.vmaddr && vmaddr < seg_end {
            let delta: u64 = vmaddr - seg.vmaddr;
            let file_off: u64 = seg.fileoff.checked_add(delta)?;
            return usize::try_from(file_off).ok();
        }
    }
    None
}

#[must_use]
pub const fn decode_bound_pointer(raw: u64, base: u64) -> u64 {
    if raw == 0 {
        return 0;
    }
    let low: u64 = raw & CHAINED_PTR_TARGET_MASK;
    let has_high_bits: bool = raw & !CHAINED_PTR_TARGET_MASK != 0;
    if has_high_bits || raw < base {
        base.wrapping_add(low)
    } else {
        raw
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SliceView<'a> {
    bytes: &'a [u8],
    base: u64,
    endian: Endian,
    encrypted: Option<EncryptedRegion>,
}

impl<'a> SliceView<'a> {
    #[must_use]
    pub fn new(bytes: &'a [u8], parsed: &ParsedSlice) -> Option<Self> {
        Some(Self {
            bytes,
            base: image_base(parsed)?,
            endian: parsed.header.endian,
            encrypted: encrypted_region(parsed),
        })
    }

    #[must_use]
    pub const fn encrypted(&self) -> Option<EncryptedRegion> {
        self.encrypted
    }

    #[must_use]
    pub fn readable(&self, off: usize, len: usize) -> bool {
        let Some(region): Option<EncryptedRegion> = self.encrypted else {
            return true;
        };
        let start: u64 = u64::try_from(off).unwrap_or(u64::MAX);
        let span: u64 = u64::try_from(len).unwrap_or(u64::MAX);
        !region.overlaps(start, span)
    }

    #[must_use]
    pub const fn base(&self) -> u64 {
        self.base
    }

    #[must_use]
    pub const fn endian(&self) -> Endian {
        self.endian
    }

    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    #[must_use]
    pub fn read_u32_at(&self, off: usize) -> Option<u32> {
        let end: usize = off.checked_add(4)?;
        if !self.readable(off, 4) {
            return None;
        }
        let raw: &[u8] = self.bytes.get(off..end)?;
        let arr: [u8; 4] = [raw[0], raw[1], raw[2], raw[3]];
        Some(match self.endian {
            Endian::Little => u32::from_le_bytes(arr),
            Endian::Big => u32::from_be_bytes(arr),
        })
    }

    #[must_use]
    pub fn read_u64_at(&self, off: usize) -> Option<u64> {
        let end: usize = off.checked_add(8)?;
        if !self.readable(off, 8) {
            return None;
        }
        let raw: &[u8] = self.bytes.get(off..end)?;
        let mut arr: [u8; 8] = [0u8; 8];
        arr.copy_from_slice(raw);
        Some(match self.endian {
            Endian::Little => u64::from_le_bytes(arr),
            Endian::Big => u64::from_be_bytes(arr),
        })
    }

    #[must_use]
    pub fn read_i32_at(&self, off: usize) -> Option<i32> {
        Some(self.read_u32_at(off)? as i32)
    }

    #[must_use]
    pub fn resolve_relative(&self, field_off: usize) -> Option<usize> {
        let rel: i32 = self.read_i32_at(field_off)?;
        if rel == 0 {
            return None;
        }
        let target: i64 = i64::try_from(field_off).ok()? + i64::from(rel);
        usize::try_from(target).ok()
    }

    #[must_use]
    pub fn resolve_indirectable_relative(&self, field_off: usize) -> Option<(usize, bool)> {
        let rel: i32 = self.read_i32_at(field_off)?;
        if rel == 0 {
            return None;
        }
        let indirect: bool = rel & 1 != 0;
        let cleared: i32 = rel & !1;
        let target: i64 = i64::try_from(field_off).ok()? + i64::from(cleared);
        let direct_off: usize = usize::try_from(target).ok()?;
        Some((direct_off, indirect))
    }

    #[must_use]
    pub fn read_pointer_at(&self, parsed: &ParsedSlice, off: usize) -> Option<u64> {
        let raw: u64 = self.read_u64_at(off)?;
        let decoded: u64 = decode_bound_pointer(raw, self.base);
        if decoded == 0 {
            return None;
        }
        let _: usize = vmaddr_to_offset(parsed, decoded)?;
        Some(decoded)
    }

    #[must_use]
    pub fn cstr_at_vmaddr(
        &self,
        parsed: &ParsedSlice,
        vmaddr: u64,
        max_len: usize,
    ) -> Option<String> {
        let off: usize = vmaddr_to_offset(parsed, vmaddr)?;
        self.cstr_at_offset(off, max_len)
    }

    #[must_use]
    pub fn cstr_at_offset(&self, off: usize, max_len: usize) -> Option<String> {
        let end_cap: usize = off.checked_add(max_len)?.min(self.bytes.len());
        let window: &[u8] = self.bytes.get(off..end_cap)?;
        let nul: usize = window.iter().position(|b: &u8| *b == 0)?;
        if !self.readable(off, nul.saturating_add(1)) {
            return None;
        }
        std::str::from_utf8(&window[..nul]).ok().map(str::to_owned)
    }

    #[must_use]
    pub fn mangled_name_at_offset(&self, off: usize, max_len: usize) -> Option<MangledName> {
        let end_cap: usize = off.checked_add(max_len)?.min(self.bytes.len());
        let window: &[u8] = self.bytes.get(off..end_cap)?;
        let mut raw: Vec<u8> = Vec::new();
        let mut refs: Vec<SymbolicRef> = Vec::new();
        let mut i: usize = 0;
        while i < window.len() {
            let b: u8 = window[i];
            if b == 0 {
                if !self.readable(off, i.saturating_add(1)) {
                    return None;
                }
                return Some(MangledName { raw, refs });
            }
            if (0x01..=0x17).contains(&b) {
                let payload_start: usize = off.checked_add(i)?.checked_add(1)?;
                let payload_end: usize = payload_start.checked_add(4)?;
                let payload: &[u8] = self.bytes.get(payload_start..payload_end)?;
                let rel: i32 = i32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let target: usize =
                    usize::try_from(i64::try_from(payload_start).ok()? + i64::from(rel)).ok()?;
                refs.push(SymbolicRef {
                    raw_index: raw.len(),
                    kind: b,
                    target,
                });
                raw.push(b);
                i += 5;
                continue;
            }
            raw.push(b);
            i += 1;
        }
        None
    }
}

#[derive(Debug, Clone)]
pub struct SymbolicRef {
    pub raw_index: usize,
    pub kind: u8,
    pub target: usize,
}

#[derive(Debug, Clone)]
pub struct MangledName {
    pub raw: Vec<u8>,
    pub refs: Vec<SymbolicRef>,
}

impl MangledName {
    #[must_use]
    pub const fn has_symbolic_ref(&self) -> bool {
        !self.refs.is_empty()
    }

    #[must_use]
    pub fn as_plain_string(&self) -> Option<String> {
        if self.has_symbolic_ref() {
            return None;
        }
        std::str::from_utf8(&self.raw).ok().map(str::to_owned)
    }
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
    fn fat_arch_count_must_fit_available_table() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&FAT_MAGIC_BE.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        let err: Error = walk_fat(&bytes).expect_err("fat table count must fit");
        assert!(
            matches!(err, Error::BadFatHeader(_)),
            "expected fat-header error, got {err}"
        );
    }

    #[test]
    fn fat_arch_count_must_stay_below_cap() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&FAT_MAGIC_BE.to_be_bytes());
        let count: u32 = u32::try_from(FAT_ARCH_COUNT_CAP + 1).expect("cap fits u32");
        bytes.extend_from_slice(&count.to_be_bytes());
        let err: Error = walk_fat(&bytes).expect_err("fat arch count must be capped");
        assert!(
            matches!(err, Error::BadFatHeader(_)),
            "expected fat-header error, got {err}"
        );
    }

    #[test]
    fn detect_magic_recognizes_slice64_le() {
        let mut bytes: [u8; 4] = [0u8; 4];
        bytes.copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        assert_eq!(detect_magic(&bytes), Some(MachoKind::Slice64Le));
    }

    #[test]
    fn slice_view_reads_honor_endianness() {
        let bytes: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
        let le: SliceView<'_> = SliceView {
            bytes: &bytes,
            base: 0,
            endian: Endian::Little,
            encrypted: None,
        };
        let be: SliceView<'_> = SliceView {
            bytes: &bytes,
            base: 0,
            endian: Endian::Big,
            encrypted: None,
        };
        assert_eq!(le.read_u32_at(0), Some(0x7856_3412));
        assert_eq!(be.read_u32_at(0), Some(0x1234_5678));
    }

    #[test]
    fn readers_reject_offsets_near_usize_max_without_overflow() {
        let bytes: [u8; 16] = [0u8; 16];
        assert!(matches!(
            u32_le(&bytes, usize::MAX - 1),
            Err(Error::Truncated(_))
        ));
        assert!(matches!(
            u32_be(&bytes, usize::MAX - 2),
            Err(Error::Truncated(_))
        ));
        assert!(matches!(
            u64_le(&bytes, usize::MAX - 3),
            Err(Error::Truncated(_))
        ));
        assert!(matches!(
            u64_be(&bytes, usize::MAX - 4),
            Err(Error::Truncated(_))
        ));
        assert!(matches!(
            read_cstr16(&bytes, usize::MAX - 5),
            Err(Error::Truncated(_))
        ));
        let view: SliceView<'_> = SliceView {
            bytes: &bytes,
            base: 0,
            endian: Endian::Little,
            encrypted: None,
        };
        assert_eq!(view.read_u32_at(usize::MAX - 1), None);
        assert_eq!(view.read_u64_at(usize::MAX - 2), None);
        assert!(u32_le(&bytes, 0).is_ok(), "in-range read still succeeds");
        assert_eq!(view.read_u32_at(0), Some(0));
    }

    #[test]
    fn relative_pointer_resolution_matches_for_both_endiannesses() {
        let mut le_bytes: [u8; 8] = [0u8; 8];
        let mut be_bytes: [u8; 8] = [0u8; 8];
        let rel: i32 = 4;
        le_bytes[..4].copy_from_slice(&rel.to_le_bytes());
        be_bytes[..4].copy_from_slice(&rel.to_be_bytes());
        le_bytes[4..].copy_from_slice(b"ok\0\0");
        be_bytes[4..].copy_from_slice(b"ok\0\0");
        let le: SliceView<'_> = SliceView {
            bytes: &le_bytes,
            base: 0,
            endian: Endian::Little,
            encrypted: None,
        };
        let be: SliceView<'_> = SliceView {
            bytes: &be_bytes,
            base: 0,
            endian: Endian::Big,
            encrypted: None,
        };
        assert_eq!(le.resolve_relative(0), Some(4));
        assert_eq!(be.resolve_relative(0), Some(4));
        assert_eq!(le.cstr_at_offset(4, 16).as_deref(), Some("ok"));
        assert_eq!(be.cstr_at_offset(4, 16).as_deref(), Some("ok"));
    }

    #[test]
    fn indirectable_relative_flags_low_bit() {
        let mut bytes: [u8; 4] = [0u8; 4];
        let rel: i32 = 9;
        bytes.copy_from_slice(&rel.to_le_bytes());
        let view: SliceView<'_> = SliceView {
            bytes: &bytes,
            base: 0,
            endian: Endian::Little,
            encrypted: None,
        };
        let (target, indirect): (usize, bool) =
            view.resolve_indirectable_relative(0).expect("resolves");
        assert!(indirect, "odd offset means indirect");
        assert_eq!(target, 8, "low bit cleared before applying delta");
    }
}
