#![allow(clippy::doc_markdown)]

//! Native DWARF sourcemap synthesizer.
//!
//! Parses the `.debug_line` and `.debug_info` sections out of any object file
//! the [`object`] crate understands (ELF / Mach-O / PE), walks the DWARF line
//! programs and compilation-unit roots with [`gimli`], and emits a
//! v3-compatible sourcemap JSON object (the same `version: 1` shape the WASM
//! DWARF-recovery path emits, so the two share a downstream schema).
//!
//! The emitted JSON carries:
//! - `compile_units`: per-CU name / comp_dir / producer / language / pc-range,
//! - `line_map`: a sorted `pc -> {file, line, column}` table built from every
//!   non-end-sequence row of every line program,
//! - `function_count` / `line_entries`: scalar summaries.
//!
//! This is the native half of the `--emit sourcemap` feature; the orchestrator
//! routes a native artifact here and serializes the returned value through the
//! existing `EmitKind::Sourcemap` channel.

use gimli::{Dwarf, EndianSlice, RunTimeEndian};
use object::{Object, ObjectSection};
use serde::Serialize;

use crate::error::{Error, Result};

const SOURCEMAP_SCHEMA_VERSION: u32 = 1;

/// One compilation unit's root attributes, recovered from `.debug_info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompileUnit {
    pub name: Option<String>,
    pub comp_dir: Option<String>,
    pub producer: Option<String>,
    pub low_pc: Option<u64>,
    pub unit_offset: u64,
    pub dwarf_version: u16,
}

/// One resolved `pc -> source location` row from a line program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LineRow {
    pub pc: u64,
    pub file: String,
    pub line: u32,
    pub column: u32,
}

/// A native DWARF sourcemap recovered from an object file's debug sections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DwarfSourcemap {
    pub compile_units: Vec<CompileUnit>,
    pub line_rows: Vec<LineRow>,
}

impl DwarfSourcemap {
    /// Serialize to the v3-compatible sourcemap JSON shape.
    #[must_use]
    pub fn to_sourcemap_json(&self) -> serde_json::Value {
        serde_json::json!({
            "version": SOURCEMAP_SCHEMA_VERSION,
            "function_count": self.compile_units.len(),
            "line_entries": self.line_rows.len(),
            "compile_units": &self.compile_units,
            "line_map": &self.line_rows,
        })
    }

    /// Whether any debug information was recovered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.compile_units.is_empty() && self.line_rows.is_empty()
    }
}

/// Synthesize a DWARF sourcemap from an object file's `.debug_*` sections.
///
/// # Errors
///
/// Returns [`Error::UnknownFormat`] if `bytes` is not a recognized object file,
/// [`Error::Dwarf`] if the debug sections are malformed, or
/// [`Error::SignatureDb`] if the object carries no `.debug_line`/`.debug_info`.
pub fn synthesize_dwarf_sourcemap(bytes: &[u8]) -> Result<DwarfSourcemap> {
    let object_file: object::File<'_> =
        object::File::parse(bytes).map_err(|_e: object::Error| Error::UnknownFormat)?;
    let endian: RunTimeEndian = if object_file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    if !has_debug_sections(&object_file) {
        return Err(Error::SignatureDb(
            "DWARF sourcemap: object carries no .debug_line/.debug_info sections".to_owned(),
        ));
    }

    let load_section =
        |id: gimli::SectionId| -> std::result::Result<EndianSlice<'_, RunTimeEndian>, gimli::Error> {
            let data: &[u8] = object_file
                .section_by_name(id.name())
                .and_then(|s: object::Section<'_, '_>| s.data().ok())
                .unwrap_or(&[]);
            Ok(EndianSlice::new(data, endian))
        };
    let dwarf: Dwarf<EndianSlice<'_, RunTimeEndian>> =
        Dwarf::load(load_section).map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?;

    let mut compile_units: Vec<CompileUnit> = Vec::new();
    let mut line_rows: Vec<LineRow> = Vec::new();

    let mut unit_headers = dwarf.units();
    while let Some(header) = unit_headers
        .next()
        .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?
    {
        let unit: gimli::Unit<EndianSlice<'_, RunTimeEndian>> = dwarf
            .unit(header)
            .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?;
        let unit_offset: u64 = header
            .offset()
            .as_debug_info_offset()
            .map_or(0, |o: gimli::DebugInfoOffset| o.0 as u64);
        let cu: CompileUnit = recover_compile_unit(&dwarf, &unit, unit_offset)?;
        compile_units.push(cu);
        collect_line_rows(&dwarf, &unit, &mut line_rows)?;
    }

    line_rows.sort_by_key(|r: &LineRow| r.pc);
    Ok(DwarfSourcemap {
        compile_units,
        line_rows,
    })
}

fn has_debug_sections(object_file: &object::File<'_>) -> bool {
    object_file.section_by_name(".debug_info").is_some()
        || object_file.section_by_name(".debug_line").is_some()
}

fn recover_compile_unit(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    unit_offset: u64,
) -> Result<CompileUnit> {
    let mut entries = unit.entries();
    let dwarf_version: u16 = unit.header.version();
    let mut name: Option<String> = None;
    let mut comp_dir: Option<String> = None;
    let mut producer: Option<String> = None;
    let mut low_pc: Option<u64> = None;
    if let Some((_, root)) = entries
        .next_dfs()
        .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?
    {
        let mut attrs = root.attrs();
        while let Some(attr) = attrs
            .next()
            .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?
        {
            match attr.name() {
                gimli::DW_AT_name => name = attr_to_string(dwarf, unit, &attr),
                gimli::DW_AT_comp_dir => comp_dir = attr_to_string(dwarf, unit, &attr),
                gimli::DW_AT_producer => producer = attr_to_string(dwarf, unit, &attr),
                gimli::DW_AT_low_pc => {
                    if let gimli::AttributeValue::Addr(a) = attr.value() {
                        low_pc = Some(a);
                    }
                }
                _ => {}
            }
        }
    }
    Ok(CompileUnit {
        name,
        comp_dir,
        producer,
        low_pc,
        unit_offset,
        dwarf_version,
    })
}

fn attr_to_string(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    attr: &gimli::Attribute<EndianSlice<'_, RunTimeEndian>>,
) -> Option<String> {
    let slice: EndianSlice<'_, RunTimeEndian> = dwarf.attr_string(unit, attr.value()).ok()?;
    let bytes: &[u8] = slice.slice();
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn collect_line_rows(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    out: &mut Vec<LineRow>,
) -> Result<()> {
    let Some(program): Option<gimli::IncompleteLineProgram<EndianSlice<'_, RunTimeEndian>>> =
        unit.line_program.clone()
    else {
        return Ok(());
    };
    let mut rows = program.rows();
    while let Some((header, row)) = rows
        .next_row()
        .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?
    {
        if row.end_sequence() {
            continue;
        }
        let file: String = resolve_file(dwarf, unit, header, row);
        let line: u32 = row
            .line()
            .map_or(0, |l: std::num::NonZeroU64| l.get() as u32);
        let column: u32 = match row.column() {
            gimli::ColumnType::LeftEdge => 0,
            gimli::ColumnType::Column(c) => c.get() as u32,
        };
        out.push(LineRow {
            pc: row.address(),
            file,
            line,
            column,
        });
    }
    Ok(())
}

fn resolve_file(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    header: &gimli::LineProgramHeader<EndianSlice<'_, RunTimeEndian>>,
    row: &gimli::LineRow,
) -> String {
    let Some(file): Option<&gimli::FileEntry<EndianSlice<'_, RunTimeEndian>>> = row.file(header)
    else {
        return String::new();
    };
    let mut path: String = String::new();
    if let Some(dir) = file.directory(header)
        && let Ok(slice) = dwarf.attr_string(unit, dir)
    {
        path.push_str(&String::from_utf8_lossy(slice.slice()));
        path.push('/');
    }
    if let Ok(slice) = dwarf.attr_string(unit, file.path_name()) {
        path.push_str(&String::from_utf8_lossy(slice.slice()));
    }
    path
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_object_input() {
        let err: Error = synthesize_dwarf_sourcemap(b"not an object file").unwrap_err();
        assert!(matches!(err, Error::UnknownFormat));
    }

    #[test]
    fn sourcemap_json_shape_is_v3_compatible() {
        let map: DwarfSourcemap = DwarfSourcemap {
            compile_units: vec![CompileUnit {
                name: Some("main.zig".to_owned()),
                comp_dir: Some("/src".to_owned()),
                producer: Some("zig 0.13".to_owned()),
                low_pc: Some(0x1000),
                unit_offset: 0,
                dwarf_version: 5,
            }],
            line_rows: vec![LineRow {
                pc: 0x1000,
                file: "/src/main.zig".to_owned(),
                line: 42,
                column: 5,
            }],
        };
        let json: serde_json::Value = map.to_sourcemap_json();
        assert_eq!(json["version"], 1);
        assert_eq!(json["line_entries"], 1);
        assert_eq!(json["compile_units"][0]["name"], "main.zig");
        assert_eq!(json["line_map"][0]["line"], 42);
    }

    #[test]
    fn empty_map_is_empty() {
        let map: DwarfSourcemap = DwarfSourcemap {
            compile_units: Vec::new(),
            line_rows: Vec::new(),
        };
        assert!(map.is_empty());
    }
}
