use std::collections::BTreeMap;
use std::io::Read as _;

use flate2::read::ZlibDecoder;
use gimli::{Dwarf, EndianSlice, RunTimeEndian};
use serde::{Deserialize, Serialize};

use crate::binary::{Endian, GoImage};
use crate::debug::{dbg_kv, dbg_line, dbg_section};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DwarfFunction {
    pub name: String,
    pub low_pc: Option<u64>,
    pub params: Vec<String>,
    pub locals: Vec<String>,
    pub type_params: Vec<String>,
}

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

const MAX_DECOMPRESSED_LEN: u64 = 1 << 30;
const MAX_ZDEBUG_INITIAL_CAPACITY: usize = 8 * 1024 * 1024;
const ZDEBUG_INITIAL_CAPACITY_FACTOR: usize = 16;
const MAX_DWARF_FUNCS: usize = 1 << 18;
const MAX_DWARF_TYPE_NAMES: usize = 1 << 16;
const MAX_DWARF_NAMES_PER_FUNC: usize = 1 << 10;
const MAX_DWARF_NAMES_TOTAL: usize = MAX_DWARF_FUNCS * MAX_DWARF_NAMES_PER_FUNC;

#[must_use]
pub fn recover_dwarf(image: &GoImage<'_>) -> DwarfReport {
    dbg_section("go.dwarf");
    let mut sections: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut compressed_seen: bool = false;
    for sec in &image.sections {
        let Some(canonical): Option<&'static str> = canonical_debug_name(&sec.name) else {
            continue;
        };
        let (data, was_compressed): (Vec<u8>, bool) =
            if sec.name.starts_with(".zdebug") || starts_with_zlib_magic(sec.data) {
                let Some(d): Option<Vec<u8>> = decompress_zdebug(sec.data) else {
                    dbg_line(|| format!("zdebug decompress failed for {}", sec.name));
                    continue;
                };
                (d, true)
            } else {
                (sec.data.to_vec(), false)
            };
        dbg_line(|| {
            format!(
                "dwarf section {} -> {canonical} ({} bytes, compressed={was_compressed})",
                sec.name,
                data.len()
            )
        });
        compressed_seen |= was_compressed;
        sections.entry(canonical.to_owned()).or_insert(data);
    }

    if !sections.contains_key(".debug_info") {
        dbg_line(|| "no .debug_info: dwarf absent (stripped or no debug build)".to_owned());
        return DwarfReport::absent();
    }
    dbg_kv("dwarf_compressed", || compressed_seen.to_string());

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
        dbg_line(|| "gimli Dwarf::load failed on the assembled debug sections".to_owned());
        return DwarfReport::absent();
    };

    let report: DwarfReport = walk_dwarf(&dwarf, compressed_seen);
    let total_params: usize = report
        .functions
        .iter()
        .map(|f: &DwarfFunction| f.params.len())
        .sum();
    let total_locals: usize = report
        .functions
        .iter()
        .map(|f: &DwarfFunction| f.locals.len())
        .sum();
    let total_type_params: usize = report
        .functions
        .iter()
        .map(|f: &DwarfFunction| f.type_params.len())
        .sum();
    dbg_kv("dwarf_version", || format!("{:?}", report.dwarf_version));
    dbg_kv("compile_units", || report.compile_units.to_string());
    dbg_line(|| {
        format!(
            "dwarf-recovery: functions={} params={total_params} locals={total_locals} \
             type_params={total_type_params} type_names={}",
            report.functions.len(),
            report.type_names.len(),
        )
    });
    report
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
    let mut total_names: usize = 0;

    while let Ok(Some((delta, entry))) = entries.next_dfs() {
        if total_names >= MAX_DWARF_NAMES_TOTAL {
            break;
        }
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
                    if func.params.len() < MAX_DWARF_NAMES_PER_FUNC
                        && let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name)
                    {
                        func.params.push(name);
                        total_names = total_names.saturating_add(1);
                    }
                }
                gimli::DW_TAG_variable => {
                    if func.locals.len() < MAX_DWARF_NAMES_PER_FUNC
                        && let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name)
                    {
                        func.locals.push(name);
                        total_names = total_names.saturating_add(1);
                    }
                }
                gimli::DW_TAG_template_type_parameter | gimli::DW_TAG_template_value_parameter => {
                    if func.type_params.len() < MAX_DWARF_NAMES_PER_FUNC
                        && let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name)
                    {
                        func.type_params.push(name);
                        total_names = total_names.saturating_add(1);
                    }
                }
                gimli::DW_TAG_typedef => {
                    if func.type_params.len() < MAX_DWARF_NAMES_PER_FUNC
                        && let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name)
                        && name.starts_with(".param")
                    {
                        func.type_params.push(name);
                        total_names = total_names.saturating_add(1);
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

fn decompress_zdebug(data: &[u8]) -> Option<Vec<u8>> {
    if !starts_with_zlib_magic(data) {
        return inflate_raw(data);
    }
    let len_bytes: [u8; 8] = data.get(4..12)?.try_into().ok()?;
    let uncompressed_len_u64: u64 = u64::from_be_bytes(len_bytes);
    if uncompressed_len_u64 > MAX_DECOMPRESSED_LEN {
        return None;
    }
    let uncompressed_len: usize = usize::try_from(uncompressed_len_u64).ok()?;
    let compressed: &[u8] = data.get(12..)?;
    let decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(compressed);
    let mut limited: std::io::Take<ZlibDecoder<&[u8]>> =
        decoder.take(uncompressed_len_u64.saturating_add(1));
    let capacity: usize = zdebug_initial_capacity(compressed.len(), uncompressed_len);
    let mut out: Vec<u8> = Vec::with_capacity(capacity);
    limited.read_to_end(&mut out).ok()?;
    if out.len() == uncompressed_len {
        Some(out)
    } else {
        None
    }
}

fn zdebug_initial_capacity(compressed_len: usize, uncompressed_len: usize) -> usize {
    compressed_len
        .saturating_mul(ZDEBUG_INITIAL_CAPACITY_FACTOR)
        .min(uncompressed_len)
        .min(MAX_ZDEBUG_INITIAL_CAPACITY)
}

fn inflate_raw(data: &[u8]) -> Option<Vec<u8>> {
    let decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(data);
    let mut limited: std::io::Take<ZlibDecoder<&[u8]>> =
        decoder.take(MAX_DECOMPRESSED_LEN.saturating_add(1));
    let mut out: Vec<u8> = Vec::new();
    limited.read_to_end(&mut out).ok()?;
    if out.is_empty() || out.len() as u64 > MAX_DECOMPRESSED_LEN {
        None
    } else {
        Some(out)
    }
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

    #[test]
    fn inflate_raw_round_trips_under_cap() {
        let payload: &[u8] = b"raw zlib debug section without the ZLIB length frame";
        let mut enc: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(payload).unwrap();
        let compressed: Vec<u8> = enc.finish().unwrap();
        let out: Vec<u8> = inflate_raw(&compressed).expect("inflate");
        assert_eq!(out, payload);
    }

    #[test]
    fn decompress_zdebug_rejects_over_cap_declared_length() {
        let mut framed: Vec<u8> = Vec::new();
        framed.extend_from_slice(ZLIB_MAGIC);
        framed.extend_from_slice(&(MAX_DECOMPRESSED_LEN + 1).to_be_bytes());
        framed.extend_from_slice(&[0u8; 8]);
        assert!(
            decompress_zdebug(&framed).is_none(),
            "a declared length above the cap must be refused before allocating"
        );
    }

    #[test]
    fn decompress_zdebug_rejects_huge_declared_length_with_tiny_payload() {
        let payload: &[u8] = b"x";
        let mut enc: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(payload).unwrap();
        let compressed: Vec<u8> = enc.finish().unwrap();
        let mut framed: Vec<u8> = Vec::new();
        framed.extend_from_slice(ZLIB_MAGIC);
        framed.extend_from_slice(&MAX_DECOMPRESSED_LEN.to_be_bytes());
        framed.extend_from_slice(&compressed);
        assert!(
            decompress_zdebug(&framed).is_none(),
            "a huge declared length with tiny compressed data is malformed"
        );
    }

    fn build_dwarf_sections(
        build: impl FnOnce(&mut gimli::write::Unit, gimli::write::UnitEntryId),
    ) -> BTreeMap<String, Vec<u8>> {
        use gimli::write::{Dwarf as WriteDwarf, EndianVec, LineProgram, Sections, Unit};
        let encoding: gimli::Encoding = gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 4,
            address_size: 8,
        };
        let mut dwarf: WriteDwarf = WriteDwarf::new();
        let unit_id: gimli::write::UnitId =
            dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit: &mut Unit = dwarf.units.get_mut(unit_id);
        let root: gimli::write::UnitEntryId = unit.root();
        build(unit, root);
        let mut sections: Sections<EndianVec<gimli::RunTimeEndian>> =
            Sections::new(EndianVec::new(gimli::RunTimeEndian::Little));
        dwarf.write(&mut sections).expect("write dwarf");
        let mut map: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        sections
            .for_each(
                |id: gimli::SectionId, w: &EndianVec<gimli::RunTimeEndian>| {
                    if !w.slice().is_empty() {
                        map.insert(id.name().to_owned(), w.slice().to_vec());
                    }
                    Ok::<(), std::convert::Infallible>(())
                },
            )
            .expect("collect sections");
        map
    }

    fn walk_from_sections(map: &BTreeMap<String, Vec<u8>>) -> DwarfReport {
        let empty: Vec<u8> = Vec::new();
        let load = |id: gimli::SectionId| -> Result<EndianSlice<'_, RunTimeEndian>, gimli::Error> {
            let data: &[u8] = map.get(id.name()).unwrap_or(&empty);
            Ok(EndianSlice::new(data, RunTimeEndian::Little))
        };
        let dwarf: Dwarf<EndianSlice<'_, RunTimeEndian>> =
            Dwarf::load(load).expect("load assembled dwarf");
        walk_dwarf(&dwarf, false)
    }

    fn set_name(unit: &mut gimli::write::Unit, id: gimli::write::UnitEntryId, name: &str) {
        unit.get_mut(id).set(
            gimli::DW_AT_name,
            gimli::write::AttributeValue::String(name.as_bytes().to_vec()),
        );
    }

    #[test]
    fn subprogram_names_are_capped_against_a_hostile_child_count() {
        let child_count: usize = MAX_DWARF_NAMES_PER_FUNC + 777;
        let map: BTreeMap<String, Vec<u8>> = build_dwarf_sections(|unit, root| {
            set_name(unit, root, "main.go");
            let sub: gimli::write::UnitEntryId = unit.add(root, gimli::DW_TAG_subprogram);
            set_name(unit, sub, "main.hostile");
            for i in 0..child_count {
                let p: gimli::write::UnitEntryId = unit.add(sub, gimli::DW_TAG_formal_parameter);
                set_name(unit, p, &format!("p{i}"));
            }
        });
        let report: DwarfReport = walk_from_sections(&map);
        let func: &DwarfFunction = report
            .functions
            .iter()
            .find(|f: &&DwarfFunction| f.name == "main.hostile")
            .expect("the subprogram is recovered");
        assert!(
            child_count > MAX_DWARF_NAMES_PER_FUNC,
            "the fixture must exceed the per-function cap to exercise it"
        );
        assert_eq!(
            func.params.len(),
            MAX_DWARF_NAMES_PER_FUNC,
            "params must stay bounded no matter how many children a subprogram declares"
        );
    }

    #[test]
    fn subprogram_recovers_params_locals_and_type_params_under_cap() {
        let map: BTreeMap<String, Vec<u8>> = build_dwarf_sections(|unit, root| {
            set_name(unit, root, "main.go");
            let sub: gimli::write::UnitEntryId = unit.add(root, gimli::DW_TAG_subprogram);
            set_name(unit, sub, "main.Add");
            for nm in ["lhs", "rhs"] {
                let p: gimli::write::UnitEntryId = unit.add(sub, gimli::DW_TAG_formal_parameter);
                set_name(unit, p, nm);
            }
            let v: gimli::write::UnitEntryId = unit.add(sub, gimli::DW_TAG_variable);
            set_name(unit, v, "sum");
            let t: gimli::write::UnitEntryId = unit.add(sub, gimli::DW_TAG_template_type_parameter);
            set_name(unit, t, "T");
        });
        let report: DwarfReport = walk_from_sections(&map);
        let func: &DwarfFunction = report
            .functions
            .iter()
            .find(|f: &&DwarfFunction| f.name == "main.Add")
            .expect("the subprogram is recovered");
        assert_eq!(func.params, vec!["lhs".to_owned(), "rhs".to_owned()]);
        assert_eq!(func.locals, vec!["sum".to_owned()]);
        assert_eq!(func.type_params, vec!["T".to_owned()]);
    }
}
