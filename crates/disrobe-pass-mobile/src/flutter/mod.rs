use std::collections::BTreeMap;

use object::Object as _;
use object::ObjectSection as _;
use object::read::{File as ObjFile, SymbolKind as ObjSymbolKind};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub mod demangler;
pub mod libapp_parser;
pub mod snapshot;

pub use demangler::{DartNameKind, DemangledName, demangle, demangle_qualified};
pub use libapp_parser::{
    DartFunctionSkeleton, DartProgramSkeleton, DartRecoveryCounts, build_program_skeleton,
    recovery_counts,
};
pub use snapshot::{
    DartFunctionBoundary, DartStaticRecovery, ImageHeader, parse_image_header, recover_dart_static,
};

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
    pub section_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotSection {
    pub symbol: String,
    pub address: u64,
    pub size: u64,
    pub bytes_preview: Vec<u8>,
}

/// Snapshot kind, matching Dart VM `Snapshot::Kind` (`runtime/vm/snapshot.h`):
/// `kFull=0, kFullJIT=1, kFullAOT=2, kModule=3, kInvalid=4`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartSnapshotKind {
    Full,
    FullJit,
    FullAot,
    Module,
    Invalid,
    Unknown(u64),
}

impl DartSnapshotKind {
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        match raw {
            0 => Self::Full,
            1 => Self::FullJit,
            2 => Self::FullAot,
            3 => Self::Module,
            4 => Self::Invalid,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn includes_code(self) -> bool {
        matches!(self, Self::FullJit | Self::FullAot | Self::Module)
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
        section_names,
    };
    for symbol in file.dynamic_symbols() {
        collect_snapshot_symbol(&file, &symbol, &mut layout);
    }
    for symbol in file.symbols() {
        collect_snapshot_symbol(&file, &symbol, &mut layout);
    }
    Ok(layout)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlutterApkLayout {
    pub libapp_path: String,
    pub libapp_size: u64,
    pub layout: LibAppLayout,
}

pub fn parse_flutter_apk(bytes: &[u8]) -> Result<FlutterApkLayout> {
    use std::io::{Cursor, Read as _};

    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut archive: zip::ZipArchive<Cursor<&[u8]>> =
        zip::ZipArchive::new(cursor).map_err(Error::from)?;
    let entry_count: usize = archive.len();
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
    let mut file: zip::read::ZipFile<'_> = archive.by_index(idx).map_err(Error::from)?;
    let libapp_path: String = file.name().to_owned();
    let mut buf: Vec<u8> = Vec::with_capacity(file.size() as usize);
    file.read_to_end(&mut buf).map_err(Error::from)?;
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

fn read_symbol_preview(file: &ObjFile<'_>, address: u64, size: u64, max: u64) -> Vec<u8> {
    let take: u64 = size.min(max);
    if take == 0 {
        return Vec::new();
    }
    for section in file.sections() {
        let s_addr: u64 = section.address();
        let s_size: u64 = section.size();
        if address >= s_addr && address + take <= s_addr + s_size {
            let off: u64 = address - s_addr;
            if let Ok(data) = section.data() {
                let off_usize: usize = off as usize;
                let take_usize: usize = take as usize;
                if off_usize + take_usize <= data.len() {
                    return data[off_usize..off_usize + take_usize].to_vec();
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
    Ok(DartAotDecompile {
        header,
        class_table_entry_estimate: class_table_estimate,
        object_pool_estimate,
        readable_strings,
        static_recovery,
    })
}

/// Decompiles a Dart AOT `libapp.so` end-to-end.
///
/// Parses the ELF, locates the isolate data and instructions snapshot sections,
/// and runs the full static recovery (function boundaries + signatures from the
/// instructions image, class and method names from the data snapshot). This is
/// the highest-fidelity entry point because it sees the instructions image,
/// which a bare snapshot blob does not.
pub fn decompile_libapp_so(bytes: &[u8]) -> Result<DartStaticRecovery> {
    let file: ObjFile<'_> =
        ObjFile::parse(bytes).map_err(|e: object::Error| Error::ElfParse(e.to_string()))?;
    let layout: LibAppLayout = parse_libapp_so(bytes)?;
    let isolate_data: Vec<u8> = section_bytes(&file, layout.isolate_snapshot_data.as_ref());
    let isolate_instructions: Vec<u8> =
        section_bytes(&file, layout.isolate_snapshot_instructions.as_ref());
    Ok(recover_dart_static(&isolate_data, &isolate_instructions))
}

#[must_use]
fn section_bytes(file: &ObjFile<'_>, section: Option<&SnapshotSection>) -> Vec<u8> {
    let Some(sec): Option<&SnapshotSection> = section else {
        return Vec::new();
    };
    for s in file.sections() {
        let s_addr: u64 = s.address();
        let s_size: u64 = s.size();
        if sec.address >= s_addr && sec.address + sec.size <= s_addr + s_size {
            let off: usize = (sec.address - s_addr) as usize;
            let end: usize = off.saturating_add(sec.size as usize);
            if let Ok(data) = s.data()
                && end <= data.len()
            {
                return data[off..end].to_vec();
            }
        }
    }
    Vec::new()
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
        let mut iter = arr.iter();
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
        let kind_field: u64 = 2;
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
        assert_eq!(header.kind_raw, 2);
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
