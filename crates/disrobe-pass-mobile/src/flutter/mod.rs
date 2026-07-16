use std::collections::BTreeMap;

use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::read::{File as ObjFile, SymbolKind as ObjSymbolKind};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub mod aot_lift;
pub mod arm64_traversal;
pub mod cid_table;
pub mod cluster;
pub mod demangler;
pub mod disasm;
pub mod kernel;
pub mod libapp_parser;
pub mod object_pool;
pub mod snapshot;
pub mod string_pool;
pub mod structured;

pub use aot_lift::{
    AotLiftReport, DartCallKind, DartCallSite, DartCheckKind, DartElidedCheck, DartLiftedFunction,
    DartPoolLoadForm, DartPoolRef, lift_functions as lift_dart_aot_functions, lift_libapp_aot,
};
pub use arm64_traversal::{
    Arm64TraversalReport, Arm64Unresolved, Arm64UnresolvedKind, traverse as traverse_arm64,
};
pub use cid_table::{
    DartCidTable, PredefinedClass, cid_table, is_application_cid,
    matches_version as cid_matches_version, predefined_classes, predefined_count, predefined_name,
};
pub use cluster::{
    ClusterFramingStatus, DartClusterRole, DartClusterSchemaReport, DartObservedCluster,
    DartReadStream, DartSnapshotFraming, attach_cluster_schema, parse_snapshot_framing,
};
pub use demangler::{DartNameKind, DemangledName, demangle, demangle_qualified};
pub use disasm::{
    Arm64Disassembly, Arm64FlowKind, Arm64Function, Arm64Instruction, disassemble_function,
    disassemble_functions, disassemble_range,
};
pub use kernel::{
    DART_KERNEL_MAGIC, DartKernel, KernelClass, KernelLibrary, KernelProcedure,
    KernelProcedureKind, KernelSource, is_dart_kernel, parse_kernel,
};
pub use libapp_parser::{
    CidTableMatch, DartFunctionSkeleton, DartLibAppRecovery, DartProgramSkeleton,
    DartRecoveryCounts, build_program_skeleton, recover_libapp, recovery_counts,
};
pub use object_pool::{
    DartPoolLiteral, DispatchSite, ObjectPoolReferenceMap, PoolSlotUse,
    recover_object_pool_references, resolve_pool_literals,
};
pub use snapshot::{
    DartClassEntry, DartFunctionBoundary, DartMethodEntry, DartNameSource, DartRecoveredFunction,
    DartSnapshotStructure, DartStaticRecovery, ImageHeader, parse_image_header,
    recover_dart_snapshot_structure, recover_dart_snapshot_structure_with_symbols,
    recover_dart_static,
};
pub use string_pool::{DartPoolString, DartStringPool, DartStringRole, recover_string_pool};

pub const DART_SNAPSHOT_MAGIC: u32 = 0xdcdc_f5f5;

const DART_SNAPSHOT_VERSION_HASH_LEN: usize = 32;
const DART_SNAPSHOT_HEADER_FIXED_LEN: usize = 4 + 8 + 8 + DART_SNAPSHOT_VERSION_HASH_LEN;
const DART_SNAPSHOT_FEATURES_MAX: usize = 4096;

pub const DART_VM_DATA_SYMBOL: &str = "_kDartVmSnapshotData";
pub const DART_VM_INSTR_SYMBOL: &str = "_kDartVmSnapshotInstructions";
pub const DART_ISOLATE_DATA_SYMBOL: &str = "_kDartIsolateSnapshotData";
pub const DART_ISOLATE_INSTR_SYMBOL: &str = "_kDartIsolateSnapshotInstructions";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibAppLayout {
    pub vm_snapshot_data: Option<SnapshotSection>,
    pub vm_snapshot_instructions: Option<SnapshotSection>,
    pub isolate_snapshot_data: Option<SnapshotSection>,
    pub isolate_snapshot_instructions: Option<SnapshotSection>,
    pub function_symbols: Vec<DartFunctionSymbol>,
    pub section_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotSection {
    pub symbol: String,
    pub address: u64,
    pub size: u64,
    pub bytes_preview: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartFunctionSymbol {
    pub offset: usize,
    pub address: u64,
    pub size: u64,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartSnapshotKind {
    Full,
    FullCore,
    FullJit,
    FullAot,
    GenSnapshot,
    Invalid,
    Unknown(u64),
}

impl DartSnapshotKind {
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        match raw {
            0 => Self::Full,
            1 => Self::FullCore,
            2 => Self::FullJit,
            3 => Self::FullAot,
            4 => Self::GenSnapshot,
            5 => Self::Invalid,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn includes_code(self) -> bool {
        matches!(self, Self::FullJit | Self::FullAot)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DartSnapshotHeader {
    pub magic: u32,
    pub length: u64,
    pub kind_raw: u64,
    pub kind: DartSnapshotKind,
    pub version_hash: String,
    pub features: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DartAotDecompile {
    pub header: DartSnapshotHeader,
    pub class_table_entry_estimate: usize,
    pub object_pool_estimate: usize,
    pub readable_strings: Vec<String>,
    pub static_recovery: DartStaticRecovery,
    pub structure: DartSnapshotStructure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlutterObfuscationMap {
    pub original_to_obfuscated: BTreeMap<String, String>,
    pub obfuscated_to_original: BTreeMap<String, String>,
    pub entries: usize,
}

pub fn parse_libapp_so(bytes: &[u8]) -> Result<LibAppLayout> {
    let file: ObjFile<'_> =
        ObjFile::parse(bytes).map_err(|e: object::Error| Error::ElfParse(e.to_string()))?;
    let mut section_names: Vec<String> = Vec::new();
    for section in file.sections() {
        let name: &str = section.name().unwrap_or("");
        if !name.is_empty() {
            section_names.push(name.to_owned());
        }
    }
    let mut layout: LibAppLayout = LibAppLayout {
        vm_snapshot_data: None,
        vm_snapshot_instructions: None,
        isolate_snapshot_data: None,
        isolate_snapshot_instructions: None,
        function_symbols: Vec::new(),
        section_names,
    };
    for symbol in file.dynamic_symbols() {
        collect_snapshot_symbol(&file, &symbol, &mut layout);
    }
    for symbol in file.symbols() {
        collect_snapshot_symbol(&file, &symbol, &mut layout);
    }
    layout.function_symbols =
        collect_function_symbols(&file, layout.isolate_snapshot_instructions.as_ref());
    Ok(layout)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlutterApkLayout {
    pub libapp_path: String,
    pub libapp_size: u64,
    pub layout: LibAppLayout,
}

pub fn parse_flutter_apk(bytes: &[u8]) -> Result<FlutterApkLayout> {
    use std::io::Cursor;

    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut archive: zip::ZipArchive<Cursor<&[u8]>> =
        zip::ZipArchive::new(cursor).map_err(Error::from)?;
    let entry_count: usize = crate::checked_zip_entry_count(archive.len())?;
    let mut libapp_index: Option<usize> = None;
    for i in 0..entry_count {
        let f: zip::read::ZipFile<'_> = archive.by_index(i).map_err(Error::from)?;
        let name: &str = f.name();
        if name.starts_with("lib/") && name.ends_with("/libapp.so") {
            libapp_index = Some(i);
            break;
        }
    }
    let Some(idx): Option<usize> = libapp_index else {
        return Err(Error::DartSectionMissing("lib/<abi>/libapp.so"));
    };
    let file: zip::read::ZipFile<'_> = archive.by_index(idx).map_err(Error::from)?;
    let libapp_path: String = file.name().to_owned();
    let buf: Vec<u8> = crate::read_zip_file_bounded(file, &libapp_path)?;
    let libapp_size: u64 = buf.len() as u64;
    let layout: LibAppLayout = parse_libapp_so(&buf)?;
    Ok(FlutterApkLayout {
        libapp_path,
        libapp_size,
        layout,
    })
}

fn collect_snapshot_symbol<'data>(
    file: &ObjFile<'data>,
    symbol: &impl object::ObjectSymbol<'data>,
    layout: &mut LibAppLayout,
) {
    let kind: ObjSymbolKind = symbol.kind();
    if !matches!(
        kind,
        ObjSymbolKind::Data | ObjSymbolKind::Text | ObjSymbolKind::Unknown
    ) {
        return;
    }
    let Ok(name): core::result::Result<&str, object::Error> = symbol.name() else {
        return;
    };
    let target: &mut Option<SnapshotSection> = match name {
        DART_VM_DATA_SYMBOL => &mut layout.vm_snapshot_data,
        DART_VM_INSTR_SYMBOL => &mut layout.vm_snapshot_instructions,
        DART_ISOLATE_DATA_SYMBOL => &mut layout.isolate_snapshot_data,
        DART_ISOLATE_INSTR_SYMBOL => &mut layout.isolate_snapshot_instructions,
        _ => return,
    };
    if target.is_some() {
        return;
    }
    let address: u64 = symbol.address();
    let size: u64 = symbol.size();
    let preview: Vec<u8> = read_symbol_preview(file, address, size, 64);
    *target = Some(SnapshotSection {
        symbol: name.to_owned(),
        address,
        size,
        bytes_preview: preview,
    });
}

fn collect_function_symbols(
    file: &ObjFile<'_>,
    isolate_instructions: Option<&SnapshotSection>,
) -> Vec<DartFunctionSymbol> {
    let Some(section): Option<&SnapshotSection> = isolate_instructions else {
        return Vec::new();
    };
    let start: u64 = section.address;
    let Some(end): Option<u64> = section.address.checked_add(section.size) else {
        return Vec::new();
    };
    let mut symbols: Vec<DartFunctionSymbol> = Vec::new();
    for symbol in file.symbols() {
        if symbol.kind() != ObjSymbolKind::Text {
            continue;
        }
        let address: u64 = symbol.address();
        let size: u64 = symbol.size();
        if size == 0 || address < start || address >= end {
            continue;
        }
        let Ok(name): core::result::Result<&str, object::Error> = symbol.name() else {
            continue;
        };
        if !is_dart_code_symbol_name(name) {
            continue;
        }
        let offset_u64: u64 = address - start;
        let Ok(offset): core::result::Result<usize, _> = usize::try_from(offset_u64) else {
            continue;
        };
        symbols.push(DartFunctionSymbol {
            offset,
            address,
            size,
            name: name.to_owned(),
        });
    }
    symbols.sort_unstable_by(|a: &DartFunctionSymbol, b: &DartFunctionSymbol| {
        a.offset.cmp(&b.offset).then_with(|| a.name.cmp(&b.name))
    });
    symbols.dedup_by(|a: &mut DartFunctionSymbol, b: &mut DartFunctionSymbol| {
        a.offset == b.offset && a.name == b.name
    });
    symbols
}

#[must_use]
fn is_dart_code_symbol_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with("_kDart")
        && !name.starts_with("stub ")
        && !name.starts_with("[Stub]")
        && name.chars().all(|c: char| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '_' | '.'
                        | '$'
                        | '<'
                        | '>'
                        | '['
                        | ']'
                        | '('
                        | ')'
                        | ','
                        | ' '
                        | ':'
                        | '-'
                        | '\''
                )
        })
}

fn read_symbol_preview(file: &ObjFile<'_>, address: u64, size: u64, max: u64) -> Vec<u8> {
    let take: u64 = size.min(max);
    if take == 0 {
        return Vec::new();
    }
    for section in file.sections() {
        let s_addr: u64 = section.address();
        let s_size: u64 = section.size();
        let Some(address_end): Option<u64> = address.checked_add(take) else {
            continue;
        };
        let Some(section_end): Option<u64> = s_addr.checked_add(s_size) else {
            continue;
        };
        if address >= s_addr && address_end <= section_end {
            let off: u64 = address - s_addr;
            if let Ok(data) = section.data() {
                let Ok(off_usize): std::result::Result<usize, std::num::TryFromIntError> =
                    usize::try_from(off)
                else {
                    continue;
                };
                let Ok(take_usize): std::result::Result<usize, std::num::TryFromIntError> =
                    usize::try_from(take)
                else {
                    continue;
                };
                let Some(end): Option<usize> = off_usize.checked_add(take_usize) else {
                    continue;
                };
                if let Some(window) = data.get(off_usize..end) {
                    return window.to_vec();
                }
            }
        }
    }
    Vec::new()
}

pub fn parse_dart_snapshot(bytes: &[u8]) -> Result<DartSnapshotHeader> {
    if bytes.len() < 4 {
        return Err(Error::DartBadMagic);
    }
    let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != DART_SNAPSHOT_MAGIC {
        return Err(Error::DartBadMagic);
    }
    if bytes.len() < DART_SNAPSHOT_HEADER_FIXED_LEN + 1 {
        return Err(Error::DartSectionMissing("snapshot-header"));
    }
    let length: u64 = u64::from_le_bytes([
        bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
    ]);
    let kind_raw: u64 = u64::from_le_bytes([
        bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19],
    ]);
    let kind: DartSnapshotKind = DartSnapshotKind::from_raw(kind_raw);
    let version_start: usize = 20;
    let version_end: usize = version_start + DART_SNAPSHOT_VERSION_HASH_LEN;
    let version_bytes: &[u8] = &bytes[version_start..version_end];
    if !version_bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(Error::DartUnknownVersion(
            String::from_utf8_lossy(version_bytes).into_owned(),
        ));
    }
    let version_hash: String = String::from_utf8_lossy(version_bytes).into_owned();
    let features_start: usize = version_end;
    let features_scan_end: usize = features_start
        .saturating_add(DART_SNAPSHOT_FEATURES_MAX)
        .min(bytes.len());
    let features_end: usize = bytes[features_start..features_scan_end]
        .iter()
        .position(|b: &u8| *b == 0)
        .map_or(features_scan_end, |p: usize| features_start + p);
    let features: String =
        String::from_utf8_lossy(&bytes[features_start..features_end]).into_owned();
    Ok(DartSnapshotHeader {
        magic,
        length,
        kind_raw,
        kind,
        version_hash,
        features,
    })
}

pub fn decompile_dart_aot(bytes: &[u8]) -> Result<DartAotDecompile> {
    let header: DartSnapshotHeader = parse_dart_snapshot(bytes)?;
    let class_table_estimate: usize = bytes
        .windows(4)
        .filter(|w: &&[u8]| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == 0x0000_0011)
        .count();
    let object_pool_estimate: usize = bytes
        .windows(4)
        .filter(|w: &&[u8]| {
            let v: u32 = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
            v == DART_SNAPSHOT_MAGIC || v == 0x000a_0001
        })
        .count();
    let readable_strings: Vec<String> = extract_readable_ascii(bytes, 4);
    let static_recovery: DartStaticRecovery = recover_dart_static(bytes, &[]);
    let structure: DartSnapshotStructure = recover_dart_snapshot_structure(bytes, &[]);
    Ok(DartAotDecompile {
        header,
        class_table_entry_estimate: class_table_estimate,
        object_pool_estimate,
        readable_strings,
        static_recovery,
        structure,
    })
}

pub fn decompile_libapp_so(bytes: &[u8]) -> Result<DartStaticRecovery> {
    let file: ObjFile<'_> =
        ObjFile::parse(bytes).map_err(|e: object::Error| Error::ElfParse(e.to_string()))?;
    let layout: LibAppLayout = parse_libapp_so(bytes)?;
    let isolate_data: Vec<u8> = section_bytes(&file, layout.isolate_snapshot_data.as_ref())?;
    let isolate_instructions: Vec<u8> =
        section_bytes(&file, layout.isolate_snapshot_instructions.as_ref())?;
    Ok(recover_dart_static(&isolate_data, &isolate_instructions))
}

pub fn decompile_libapp_so_structured(bytes: &[u8]) -> Result<DartSnapshotStructure> {
    let file: ObjFile<'_> =
        ObjFile::parse(bytes).map_err(|e: object::Error| Error::ElfParse(e.to_string()))?;
    let layout: LibAppLayout = parse_libapp_so(bytes)?;
    let isolate_data: Vec<u8> = section_bytes(&file, layout.isolate_snapshot_data.as_ref())?;
    let isolate_instructions: Vec<u8> =
        section_bytes(&file, layout.isolate_snapshot_instructions.as_ref())?;
    Ok(snapshot::recover_dart_snapshot_structure_with_symbols(
        &isolate_data,
        &isolate_instructions,
        &layout.function_symbols,
    ))
}

pub fn decompile_libapp_so_recovery(bytes: &[u8]) -> Result<libapp_parser::DartLibAppRecovery> {
    let file: ObjFile<'_> =
        ObjFile::parse(bytes).map_err(|e: object::Error| Error::ElfParse(e.to_string()))?;
    let layout: LibAppLayout = parse_libapp_so(bytes)?;
    let isolate_data: Vec<u8> = section_bytes(&file, layout.isolate_snapshot_data.as_ref())?;
    let isolate_instructions: Vec<u8> =
        section_bytes(&file, layout.isolate_snapshot_instructions.as_ref())?;
    let instructions_base: u64 = layout
        .isolate_snapshot_instructions
        .as_ref()
        .map_or(0, |s: &SnapshotSection| s.address);
    let version_hash: String = parse_dart_snapshot(&isolate_data)
        .map(|h: DartSnapshotHeader| h.version_hash)
        .unwrap_or_default();
    let static_recovery: DartStaticRecovery =
        recover_dart_static(&isolate_data, &isolate_instructions);
    Ok(libapp_parser::recover_libapp(
        &version_hash,
        &isolate_data,
        instructions_base,
        &isolate_instructions,
        &static_recovery,
    ))
}

pub(crate) fn isolate_instruction_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    let file: ObjFile<'_> =
        ObjFile::parse(bytes).map_err(|e: object::Error| Error::ElfParse(e.to_string()))?;
    let layout: LibAppLayout = parse_libapp_so(bytes)?;
    section_bytes(&file, layout.isolate_snapshot_instructions.as_ref())
}

pub(crate) fn isolate_data_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    let file: ObjFile<'_> =
        ObjFile::parse(bytes).map_err(|e: object::Error| Error::ElfParse(e.to_string()))?;
    let layout: LibAppLayout = parse_libapp_so(bytes)?;
    section_bytes(&file, layout.isolate_snapshot_data.as_ref())
}

pub fn disassemble_libapp_so(bytes: &[u8]) -> Result<disasm::Arm64Disassembly> {
    let file: ObjFile<'_> =
        ObjFile::parse(bytes).map_err(|e: object::Error| Error::ElfParse(e.to_string()))?;
    let layout: LibAppLayout = parse_libapp_so(bytes)?;
    let isolate_instructions: Vec<u8> =
        section_bytes(&file, layout.isolate_snapshot_instructions.as_ref())?;
    let recovery: DartStaticRecovery = recover_dart_static(&[], &isolate_instructions);
    let entries: Vec<usize> = recovery
        .function_boundaries
        .iter()
        .map(|b: &DartFunctionBoundary| b.offset)
        .collect::<Vec<usize>>();
    let names_by_offset: std::collections::BTreeMap<usize, String> = layout
        .function_symbols
        .iter()
        .map(|s: &DartFunctionSymbol| (s.offset, s.name.clone()))
        .collect();
    let names: Vec<Option<String>> = entries
        .iter()
        .map(|entry: &usize| names_by_offset.get(entry).cloned())
        .collect();
    Ok(disasm::disassemble_functions(
        &isolate_instructions,
        0,
        &entries,
        &names,
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DartKernelDecompile {
    pub kernel: kernel::DartKernel,
    pub recovered_source: String,
}

pub fn decompile_dart_kernel(bytes: &[u8]) -> Result<DartKernelDecompile> {
    let parsed: kernel::DartKernel = kernel::parse_kernel(bytes)?;
    let recovered_source: String = parsed
        .sources
        .iter()
        .filter(|s: &&kernel::KernelSource| !s.text.is_empty())
        .map(|s: &kernel::KernelSource| s.text.clone())
        .collect::<Vec<String>>()
        .join("\n");
    Ok(DartKernelDecompile {
        kernel: parsed,
        recovered_source,
    })
}

fn section_bytes(file: &ObjFile<'_>, section: Option<&SnapshotSection>) -> Result<Vec<u8>> {
    let Some(sec): Option<&SnapshotSection> = section else {
        return Ok(Vec::new());
    };
    for s in file.sections() {
        let s_addr: u64 = s.address();
        let s_size: u64 = s.size();
        let Some(sec_end): Option<u64> = sec.address.checked_add(sec.size) else {
            continue;
        };
        let Some(section_end): Option<u64> = s_addr.checked_add(s_size) else {
            continue;
        };
        if sec.address >= s_addr && sec_end <= section_end {
            let Ok(off): std::result::Result<usize, std::num::TryFromIntError> =
                usize::try_from(sec.address - s_addr)
            else {
                continue;
            };
            let Ok(size): std::result::Result<usize, std::num::TryFromIntError> =
                usize::try_from(sec.size)
            else {
                continue;
            };
            let Some(end): Option<usize> = off.checked_add(size) else {
                continue;
            };
            if let Ok(data) = s.data()
                && let Some(window) = data.get(off..end)
            {
                return Ok(window.to_vec());
            }
        }
    }
    Err(Error::DartSectionOutOfBounds {
        section: sec.symbol.clone(),
    })
}

fn extract_readable_ascii(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    for byte in bytes {
        if (0x20..0x7f).contains(byte) {
            current.push(*byte);
        } else {
            if current.len() >= min_len
                && let Ok(s) = std::str::from_utf8(&current)
            {
                out.push(s.to_owned());
            }
            current.clear();
        }
    }
    if current.len() >= min_len
        && let Ok(s) = std::str::from_utf8(&current)
    {
        out.push(s.to_owned());
    }
    out
}

pub fn parse_flutter_obfuscation_map(bytes: &[u8]) -> Result<FlutterObfuscationMap> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e: serde_json::Error| Error::FlutterMapMalformed(e.to_string()))?;
    let mut original_to_obfuscated: BTreeMap<String, String> = BTreeMap::new();
    let mut obfuscated_to_original: BTreeMap<String, String> = BTreeMap::new();
    if let Some(arr) = value.as_array() {
        if arr.len() % 2 != 0 {
            return Err(Error::FlutterMapMalformed(
                "expected even-length array".to_owned(),
            ));
        }
        let mut iter: core::slice::Iter<'_, serde_json::Value> = arr.iter();
        while let (Some(a), Some(b)) = (iter.next(), iter.next()) {
            let original: String = a
                .as_str()
                .ok_or_else(|| Error::FlutterMapMalformed("non-string entry".to_owned()))?
                .to_owned();
            let obfuscated: String = b
                .as_str()
                .ok_or_else(|| Error::FlutterMapMalformed("non-string entry".to_owned()))?
                .to_owned();
            obfuscated_to_original.insert(obfuscated.clone(), original.clone());
            original_to_obfuscated.insert(original, obfuscated);
        }
    } else if let Some(map) = value.as_object() {
        for (k, v) in map {
            let obfuscated: String = v
                .as_str()
                .ok_or_else(|| Error::FlutterMapMalformed("non-string mapping value".to_owned()))?
                .to_owned();
            obfuscated_to_original.insert(obfuscated.clone(), k.clone());
            original_to_obfuscated.insert(k.clone(), obfuscated);
        }
    } else {
        return Err(Error::FlutterMapMalformed(
            "expected JSON array or object".to_owned(),
        ));
    }
    let entries: usize = original_to_obfuscated.len();
    Ok(FlutterObfuscationMap {
        original_to_obfuscated,
        obfuscated_to_original,
        entries,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    pub(crate) fn synth_minimal_dart_snapshot(features: &str) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&DART_SNAPSHOT_MAGIC.to_le_bytes());
        let length_field: u64 = 1024;
        buf.extend_from_slice(&length_field.to_le_bytes());
        let kind_field: u64 = 3;
        buf.extend_from_slice(&kind_field.to_le_bytes());
        let version_hash: [u8; 32] = *b"abcdef0123456789abcdef0123456789";
        buf.extend_from_slice(&version_hash);
        buf.extend_from_slice(features.as_bytes());
        buf.push(0u8);
        for i in 0..256u32 {
            buf.extend_from_slice(&i.to_le_bytes());
        }
        buf.extend_from_slice(b"\x00hello_dart_class\x00");
        buf
    }

    #[test]
    fn parse_dart_snapshot_round_trip() {
        let bytes: Vec<u8> = synth_minimal_dart_snapshot("product no-causal_async_stacks");
        let header: DartSnapshotHeader = parse_dart_snapshot(&bytes).expect("parse snap");
        assert_eq!(header.magic, DART_SNAPSHOT_MAGIC);
        assert_eq!(header.length, 1024);
        assert_eq!(header.kind_raw, 3);
        assert_eq!(header.kind, DartSnapshotKind::FullAot);
        assert_eq!(header.version_hash, "abcdef0123456789abcdef0123456789");
        assert!(header.features.contains("product"));
    }

    #[test]
    fn parse_dart_snapshot_bad_magic_rejected() {
        let mut bytes: Vec<u8> = synth_minimal_dart_snapshot("x");
        bytes[0] = 0xff;
        let err: Error = parse_dart_snapshot(&bytes).expect_err("must fail");
        assert!(matches!(err, Error::DartBadMagic));
    }

    #[test]
    fn decompile_dart_aot_returns_strings() {
        let bytes: Vec<u8> = synth_minimal_dart_snapshot("test");
        let report: DartAotDecompile = decompile_dart_aot(&bytes).expect("decompile");
        assert_eq!(report.header.magic, DART_SNAPSHOT_MAGIC);
        assert!(
            report
                .readable_strings
                .iter()
                .any(|s: &String| s.contains("hello_dart_class"))
        );
    }

    #[test]
    fn obfuscation_map_array_format() {
        let json: &[u8] = br#"["originalName","ABC","anotherName","xyz"]"#;
        let map: FlutterObfuscationMap = parse_flutter_obfuscation_map(json).expect("parse map");
        assert_eq!(map.entries, 2);
        assert_eq!(
            map.obfuscated_to_original.get("ABC").map(String::as_str),
            Some("originalName")
        );
        assert_eq!(
            map.original_to_obfuscated
                .get("anotherName")
                .map(String::as_str),
            Some("xyz")
        );
    }

    #[test]
    fn obfuscation_map_object_format() {
        let json: &[u8] = br#"{"foo":"a","bar":"b"}"#;
        let map: FlutterObfuscationMap = parse_flutter_obfuscation_map(json).expect("parse");
        assert_eq!(map.entries, 2);
        assert_eq!(
            map.obfuscated_to_original.get("a").map(String::as_str),
            Some("foo")
        );
    }

    #[test]
    fn obfuscation_map_rejects_odd_array() {
        let json: &[u8] = br#"["a"]"#;
        let err: Error = parse_flutter_obfuscation_map(json).expect_err("must fail");
        assert!(matches!(err, Error::FlutterMapMalformed(_)));
    }
}
