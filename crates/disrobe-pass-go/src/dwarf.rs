use std::collections::BTreeMap;
use std::io::Read as _;

use flate2::read::ZlibDecoder;
use gimli::{Dwarf, EndianSlice, RunTimeEndian};
use serde::{Deserialize, Serialize};

use crate::binary::{Endian, GoImage};

/// One function recovered from DWARF, carrying the parameter, local-variable, and
/// type-parameter names that never appear in the pclntab funcname table.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DwarfFunction {
    pub name: String,
    pub low_pc: Option<u64>,
    pub params: Vec<String>,
    pub locals: Vec<String>,
    pub type_params: Vec<String>,
}

/// DWARF-derived recovery layered on top of the pclntab analysis. Present only when a
/// binary kept its debug info (built without `-ldflags=-w`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DwarfReport {
    pub present: bool,
    pub compressed: bool,
    pub dwarf_version: Option<u16>,
    pub compile_units: u32,
    pub functions: Vec<DwarfFunction>,
    pub type_names: Vec<String>,
}

impl DwarfReport {
    #[must_use]
    pub const fn absent() -> Self {
        Self {
            present: false,
            compressed: false,
            dwarf_version: None,
            compile_units: 0,
            functions: Vec::new(),
            type_names: Vec::new(),
        }
    }
}

const ZLIB_MAGIC: &[u8; 4] = b"ZLIB";
const MAX_DWARF_FUNCS: usize = 1 << 18;
const MAX_DWARF_TYPE_NAMES: usize = 1 << 16;

/// Recovers parameter/local/type-parameter names from a binary's plain `.debug_*` or zlib `.zdebug_*` DWARF.
#[must_use]
pub fn recover_dwarf(image: &GoImage<'_>) -> DwarfReport {
    let mut sections: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut compressed_seen: bool = false;
    for sec in &image.sections {
        let Some(canonical): Option<&'static str> = canonical_debug_name(&sec.name) else {
            continue;
        };
        let (data, was_compressed): (Vec<u8>, bool) =
            if sec.name.starts_with(".zdebug") || starts_with_zlib_magic(sec.data) {
                match decompress_zdebug(sec.data) {
                    Some(d) => (d, true),
                    None => continue,
                }
            } else {
                (sec.data.to_vec(), false)
            };
        compressed_seen |= was_compressed;
        sections.entry(canonical.to_owned()).or_insert(data);
    }

    if !sections.contains_key(".debug_info") {
        return DwarfReport::absent();
    }

    let endian: RunTimeEndian = match image.endian {
        Endian::Little => RunTimeEndian::Little,
        Endian::Big => RunTimeEndian::Big,
    };
    let empty: Vec<u8> = Vec::new();
    let load = |id: gimli::SectionId| -> Result<EndianSlice<'_, RunTimeEndian>, gimli::Error> {
        let data: &[u8] = sections.get(id.name()).unwrap_or(&empty);
        Ok(EndianSlice::new(data, endian))
    };
    let Ok(dwarf): Result<Dwarf<EndianSlice<'_, RunTimeEndian>>, _> = Dwarf::load(load) else {
        return DwarfReport::absent();
    };

    walk_dwarf(&dwarf, compressed_seen)
}

fn walk_dwarf(dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>, compressed: bool) -> DwarfReport {
    let mut functions: Vec<DwarfFunction> = Vec::new();
    let mut type_names: Vec<String> = Vec::new();
    let mut compile_units: u32 = 0;
    let mut dwarf_version: Option<u16> = None;

    let mut headers: gimli::DebugInfoUnitHeadersIter<EndianSlice<'_, RunTimeEndian>> =
        dwarf.units();
    while let Ok(Some(header)) = headers.next() {
        let Ok(unit): Result<gimli::Unit<EndianSlice<'_, RunTimeEndian>>, _> = dwarf.unit(header)
        else {
            continue;
        };
        compile_units = compile_units.saturating_add(1);
        dwarf_version.get_or_insert_with(|| unit.header.version());
        collect_unit(dwarf, &unit, &mut functions, &mut type_names);
        if functions.len() >= MAX_DWARF_FUNCS || type_names.len() >= MAX_DWARF_TYPE_NAMES {
            break;
        }
    }

    functions.sort();
    functions.dedup();
    type_names.sort();
    type_names.dedup();

    DwarfReport {
        present: true,
        compressed,
        dwarf_version,
        compile_units,
        functions,
        type_names,
    }
}

fn collect_unit(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    functions: &mut Vec<DwarfFunction>,
    type_names: &mut Vec<String>,
) {
    let mut entries: gimli::EntriesCursor<'_, '_, EndianSlice<'_, RunTimeEndian>> = unit.entries();
    let mut current: Option<DwarfFunction> = None;
    let mut func_depth: isize = isize::MIN;
    let mut depth: isize = 0;

    while let Ok(Some((delta, entry))) = entries.next_dfs() {
        depth += delta;
        if current.is_some() && depth <= func_depth {
            if let Some(done) = current.take() {
                push_function(functions, done);
            }
            func_depth = isize::MIN;
        }
        let tag: gimli::DwTag = entry.tag();
        if tag == gimli::DW_TAG_subprogram {
            if let Some(done) = current.take() {
                push_function(functions, done);
            }
            if let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name) {
                current = Some(DwarfFunction {
                    name,
                    low_pc: attr_low_pc(dwarf, unit, entry),
                    params: Vec::new(),
                    locals: Vec::new(),
                    type_params: Vec::new(),
                });
                func_depth = depth;
            }
            continue;
        }
        if let Some(func) = current.as_mut()
            && depth == func_depth + 1
        {
            match tag {
                gimli::DW_TAG_formal_parameter => {
                    if let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name) {
                        func.params.push(name);
                    }
                }
                gimli::DW_TAG_variable => {
                    if let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name) {
                        func.locals.push(name);
                    }
                }
                gimli::DW_TAG_template_type_parameter | gimli::DW_TAG_template_value_parameter => {
                    if let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name) {
                        func.type_params.push(name);
                    }
                }
                gimli::DW_TAG_typedef => {
                    if let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name)
                        && name.starts_with(".param")
                    {
                        func.type_params.push(name);
                    }
                }
                _ => {}
            }
            continue;
        }
        if matches!(
            tag,
            gimli::DW_TAG_structure_type
                | gimli::DW_TAG_class_type
                | gimli::DW_TAG_typedef
                | gimli::DW_TAG_union_type
                | gimli::DW_TAG_enumeration_type
        ) && current.is_none()
            && let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name)
            && type_names.len() < MAX_DWARF_TYPE_NAMES
        {
            type_names.push(name);
        }
    }
    if let Some(done) = current.take() {
        push_function(functions, done);
    }
}

fn push_function(functions: &mut Vec<DwarfFunction>, func: DwarfFunction) {
    if functions.len() < MAX_DWARF_FUNCS {
        functions.push(func);
    }
}

fn attr_string(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>>,
    attr: gimli::DwAt,
) -> Option<String> {
    let value: gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>> =
        entry.attr_value(attr).ok()??;
    let slice: EndianSlice<'_, RunTimeEndian> = dwarf.attr_string(unit, value).ok()?;
    let text: &str = std::str::from_utf8(slice.slice()).ok()?;
    if text.is_empty() {
        None
    } else {
        Some(text.to_owned())
    }
}

fn attr_low_pc(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>>,
) -> Option<u64> {
    let value: gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>> =
        entry.attr_value(gimli::DW_AT_low_pc).ok()??;
    match value {
        gimli::AttributeValue::Addr(a) => Some(a),
        gimli::AttributeValue::DebugAddrIndex(index) => dwarf.address(unit, index).ok(),
        _ => None,
    }
}

fn canonical_debug_name(name: &str) -> Option<&'static str> {
    let stem: &str = name
        .strip_prefix(".zdebug_")
        .or_else(|| name.strip_prefix(".debug_"))
        .or_else(|| name.strip_prefix("__zdebug_"))
        .or_else(|| name.strip_prefix("__debug_"))?;
    Some(match stem {
        "info" => ".debug_info",
        "abbrev" => ".debug_abbrev",
        "str" => ".debug_str",
        "str_offsets" | "str_offs" => ".debug_str_offsets",
        "line" => ".debug_line",
        "line_str" => ".debug_line_str",
        "ranges" => ".debug_ranges",
        "rnglists" => ".debug_rnglists",
        "loc" => ".debug_loc",
        "loclists" => ".debug_loclists",
        "addr" => ".debug_addr",
        "types" => ".debug_types",
        _ => return None,
    })
}

fn starts_with_zlib_magic(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == ZLIB_MAGIC
}

/// Decompress a Go `.zdebug_*` payload: `"ZLIB"` + 8-byte big-endian length + zlib.
fn decompress_zdebug(data: &[u8]) -> Option<Vec<u8>> {
    if !starts_with_zlib_magic(data) {
        return inflate_raw(data);
    }
    let len_bytes: [u8; 8] = data.get(4..12)?.try_into().ok()?;
    let uncompressed_len: usize = usize::try_from(u64::from_be_bytes(len_bytes)).ok()?;
    if uncompressed_len > (1 << 30) {
        return None;
    }
    let mut decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(&data[12..]);
    let mut out: Vec<u8> = Vec::with_capacity(uncompressed_len);
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

fn inflate_raw(data: &[u8]) -> Option<Vec<u8>> {
    let mut decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(data);
    let mut out: Vec<u8> = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    if out.is_empty() { None } else { Some(out) }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write as _;

    #[test]
    fn canonical_names_map_zdebug_and_debug() {
        assert_eq!(canonical_debug_name(".zdebug_info"), Some(".debug_info"));
        assert_eq!(canonical_debug_name(".debug_abbrev"), Some(".debug_abbrev"));
        assert_eq!(canonical_debug_name(".zdebug_str"), Some(".debug_str"));
        assert_eq!(canonical_debug_name("__zdebug_line"), Some(".debug_line"));
        assert_eq!(canonical_debug_name(".text"), None);
        assert_eq!(canonical_debug_name(".debug_gdb_scripts"), None);
    }

    #[test]
    fn zdebug_roundtrip_decompresses() {
        let payload: &[u8] = b"the quick brown fox debugging info payload";
        let mut enc: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(payload).unwrap();
        let compressed: Vec<u8> = enc.finish().unwrap();
        let mut framed: Vec<u8> = Vec::new();
        framed.extend_from_slice(ZLIB_MAGIC);
        framed.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        framed.extend_from_slice(&compressed);
        let out: Vec<u8> = decompress_zdebug(&framed).expect("decompress");
        assert_eq!(out, payload);
    }

    #[test]
    fn zlib_magic_detection() {
        assert!(starts_with_zlib_magic(b"ZLIB\x00\x00\x00\x00"));
        assert!(!starts_with_zlib_magic(b"\x78\x9c"));
        assert!(!starts_with_zlib_magic(b"ZL"));
    }

    #[test]
    fn absent_report_is_empty() {
        let r: DwarfReport = DwarfReport::absent();
        assert!(!r.present);
        assert!(r.functions.is_empty());
    }
}
