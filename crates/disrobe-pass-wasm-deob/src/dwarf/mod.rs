use std::collections::BTreeMap;

use gimli::{Dwarf, Unit};

use crate::dwarf::parse::extract;
use crate::dwarf::unit::{CompileUnitInfo, Slice, UnitBundle, load_dwarf, walk_units};
use crate::error::Result;

pub mod lines;
pub mod output;
pub mod parse;
pub mod symbols;
pub mod types;
pub mod unit;

pub use lines::{LineMap, Pc, SourceLocation};
pub use output::{CompileUnitSummary, WasmDwarfRecovery};
pub use parse::DwarfSections;
pub use symbols::{FunctionId, FunctionInfo, ParameterInfo, SymbolTable, TypeRef, VariableInfo};
pub use types::{BaseEncoding, DwarfTypeGraph, MemberRecord, RecoveredDwarfType};

#[must_use]
pub fn function_banner(recovery: &WasmDwarfRecovery, pc: u64) -> Option<String> {
    let func: &FunctionInfo = recovery.function_for_pc(pc)?;
    let name: &str = func.name.as_deref().unwrap_or("<anonymous>");
    let source: &str = func.source_file.as_deref().unwrap_or("<unknown>");
    let line: u32 = func.decl_line.unwrap_or(0);
    Some(format!("{name} at {source}:{line}"))
}

#[must_use]
pub fn line_for_pc(recovery: &WasmDwarfRecovery, pc: u64) -> Option<SourceLocation> {
    recovery.resolve_pc(pc).cloned()
}

pub fn recover_source_map(input: &[u8]) -> Result<WasmDwarfRecovery> {
    let sections: DwarfSections = extract(input)?;
    if sections.is_empty() {
        return Ok(WasmDwarfRecovery::default());
    }
    let total_bytes: usize = sections.total_bytes();
    let dwarf: Dwarf<Slice<'_>> = load_dwarf(&sections)?;
    let bundles: Vec<UnitBundle> = walk_units(&dwarf)?;
    let compile_units: Vec<CompileUnitInfo> = bundles
        .iter()
        .map(|b: &UnitBundle| b.compile_unit.clone())
        .collect::<Vec<_>>();
    let line_map: LineMap = build_line_map(&dwarf)?;
    let file_lookup: BTreeMap<(u64, u64), String> = build_file_index(&dwarf)?;
    let symbols: SymbolTable = symbols::build(&bundles, &|unit_offset: u64, file_index: u64| {
        file_lookup.get(&(unit_offset, file_index)).cloned()
    });
    let type_graph: DwarfTypeGraph = types::build(&bundles);
    Ok(output::assemble(
        compile_units,
        symbols,
        line_map,
        type_graph,
        total_bytes,
    ))
}

pub fn has_dwarf(input: &[u8]) -> Result<bool> {
    Ok(extract(input)?.has_any())
}

fn build_line_map(dwarf: &Dwarf<Slice<'_>>) -> Result<LineMap> {
    let mut combined: LineMap = LineMap::default();
    let mut headers: gimli::DebugInfoUnitHeadersIter<Slice<'_>> = dwarf.units();
    while let Some(header) = headers
        .next()
        .map_err(|e: gimli::Error| crate::error::Error::Parse(format!("dwarf units: {e}")))?
    {
        let unit: Unit<Slice<'_>> = dwarf
            .unit(header)
            .map_err(|e: gimli::Error| crate::error::Error::Parse(format!("dwarf unit: {e}")))?;
        let unit_map: LineMap = lines::build(dwarf, &unit)?;
        for (pc, loc) in unit_map.entries {
            combined.entries.insert(pc, loc);
        }
    }
    Ok(combined)
}

fn build_file_index(dwarf: &Dwarf<Slice<'_>>) -> Result<BTreeMap<(u64, u64), String>> {
    use gimli::Reader;
    let mut out: BTreeMap<(u64, u64), String> = BTreeMap::new();
    let mut headers: gimli::DebugInfoUnitHeadersIter<Slice<'_>> = dwarf.units();
    while let Some(header) = headers
        .next()
        .map_err(|e: gimli::Error| crate::error::Error::Parse(format!("dwarf units: {e}")))?
    {
        let unit: Unit<Slice<'_>> = dwarf
            .unit(header)
            .map_err(|e: gimli::Error| crate::error::Error::Parse(format!("dwarf unit: {e}")))?;
        let unit_offset: u64 = match unit.header.offset() {
            gimli::UnitSectionOffset::DebugInfoOffset(o) => o.0 as u64,
            gimli::UnitSectionOffset::DebugTypesOffset(o) => o.0 as u64,
        };
        let Some(program): Option<gimli::IncompleteLineProgram<Slice<'_>, usize>> =
            unit.line_program.clone()
        else {
            continue;
        };
        let header_data: gimli::LineProgramHeader<Slice<'_>, usize> = program.header().clone();
        let comp_dir: Option<String> = match unit.comp_dir.as_ref() {
            Some(r) => Some(
                Reader::to_string_lossy(r)
                    .map_err(|e: gimli::Error| {
                        crate::error::Error::Parse(format!("dwarf cu: {e}"))
                    })?
                    .into_owned(),
            ),
            None => None,
        };
        for (idx, file) in header_data.file_names().iter().enumerate() {
            let resolved_idx: u64 = if header_data.version() < 5 {
                idx as u64 + 1
            } else {
                idx as u64
            };
            let name_reader: Slice<'_> = dwarf
                .attr_string(&unit, file.path_name())
                .map_err(|e: gimli::Error| crate::error::Error::Parse(format!("file path: {e}")))?;
            let name: String = Reader::to_string_lossy(&name_reader)
                .map_err(|e: gimli::Error| crate::error::Error::Parse(format!("file lossy: {e}")))?
                .into_owned();
            let dir: Option<String> = match file.directory(&header_data) {
                Some(dir_attr) => {
                    let dir_reader: Slice<'_> =
                        dwarf
                            .attr_string(&unit, dir_attr)
                            .map_err(|e: gimli::Error| {
                                crate::error::Error::Parse(format!("file dir: {e}"))
                            })?;
                    Some(
                        Reader::to_string_lossy(&dir_reader)
                            .map_err(|e: gimli::Error| {
                                crate::error::Error::Parse(format!("dir lossy: {e}"))
                            })?
                            .into_owned(),
                    )
                }
                None => None,
            };
            let combined_path: String = combine_path(comp_dir.as_deref(), dir.as_deref(), &name);
            out.insert((unit_offset, resolved_idx), combined_path);
        }
    }
    Ok(out)
}

fn combine_path(comp_dir: Option<&str>, dir: Option<&str>, name: &str) -> String {
    let raw: String = match (dir, comp_dir) {
        (Some(d), _) if is_absolute(d) => join(d, name),
        (Some(d), Some(base)) => join(&join(base, d), name),
        (Some(d), None) => join(d, name),
        (None, Some(base)) => join(base, name),
        (None, None) => name.to_string(),
    };
    raw.replace('\\', "/")
}

#[inline]
fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
        || path.starts_with('\\')
        || (path.len() >= 2 && path.as_bytes()[1] == b':')
}

#[inline]
fn join(a: &str, b: &str) -> String {
    if a.is_empty() {
        return b.to_string();
    }
    if b.is_empty() {
        return a.to_string();
    }
    if a.ends_with('/') || a.ends_with('\\') {
        format!("{a}{b}")
    } else {
        format!("{a}/{b}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const EMPTY_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    #[test]
    fn empty_module_returns_empty_recovery() {
        let recovery: WasmDwarfRecovery = recover_source_map(EMPTY_WASM).unwrap();
        assert!(recovery.is_empty());
        assert_eq!(recovery.function_count(), 0);
        assert_eq!(recovery.line_entry_count(), 0);
        assert_eq!(recovery.type_count(), 0);
        assert_eq!(recovery.section_bytes, 0);
    }

    #[test]
    fn has_dwarf_returns_false_for_empty_module() {
        assert!(!has_dwarf(EMPTY_WASM).unwrap());
    }
}
