use std::collections::BTreeMap;

use serde::Serialize;

use crate::dwarf::lines::{LineMap, Pc, SourceLocation};
use crate::dwarf::symbols::{FunctionInfo, SymbolTable};
use crate::dwarf::types::DwarfTypeGraph;
use crate::dwarf::unit::CompileUnitInfo;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct WasmDwarfRecovery {
    pub sources: BTreeMap<String, Vec<CompileUnitSummary>>,
    pub functions: BTreeMap<u64, FunctionInfo>,
    pub line_map: BTreeMap<Pc, SourceLocation>,
    pub types: DwarfTypeGraph,
    pub compile_units: Vec<CompileUnitSummary>,
    pub section_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompileUnitSummary {
    pub name: Option<String>,
    pub comp_dir: Option<String>,
    pub producer: Option<String>,
    pub language: Option<String>,
    pub low_pc: Option<u64>,
    pub high_pc: Option<u64>,
    pub unit_offset: u64,
}

impl WasmDwarfRecovery {
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty() && self.line_map.is_empty() && self.types.is_empty()
    }

    #[inline]
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    #[inline]
    #[must_use]
    pub fn line_entry_count(&self) -> usize {
        self.line_map.len()
    }

    #[inline]
    #[must_use]
    pub fn type_count(&self) -> usize {
        self.types.len()
    }

    #[must_use]
    pub fn resolve_pc(&self, pc: Pc) -> Option<&SourceLocation> {
        self.line_map
            .range(..=pc)
            .next_back()
            .map(|(_, loc): (&Pc, &SourceLocation)| loc)
    }

    #[must_use]
    pub fn function_for_pc(&self, pc: u64) -> Option<&FunctionInfo> {
        self.functions
            .values()
            .find(|f: &&FunctionInfo| match (f.low_pc, f.high_pc) {
                (Some(low), Some(high)) => pc >= low && pc < high,
                _ => false,
            })
    }

    #[must_use]
    pub fn to_sourcemap_json(&self) -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "function_count": self.function_count(),
            "line_entries": self.line_entry_count(),
            "type_count": self.type_count(),
            "compile_units": &self.compile_units,
            "functions": &self.functions,
            "line_map": self
                .line_map
                .iter()
                .map(|(pc, loc): (&Pc, &SourceLocation)| {
                    serde_json::json!({
                        "pc": pc,
                        "file": loc.file,
                        "line": loc.line,
                        "column": loc.column,
                    })
                })
                .collect::<Vec<_>>(),
        })
    }
}

pub fn assemble(
    compile_units: Vec<CompileUnitInfo>,
    symbols: SymbolTable,
    lines: LineMap,
    types: DwarfTypeGraph,
    section_bytes: usize,
) -> WasmDwarfRecovery {
    let summaries: Vec<CompileUnitSummary> = compile_units
        .into_iter()
        .map(|cu: CompileUnitInfo| CompileUnitSummary {
            name: cu.name,
            comp_dir: cu.comp_dir,
            producer: cu.producer,
            language: cu.language,
            low_pc: cu.low_pc,
            high_pc: cu.high_pc,
            unit_offset: cu.unit_offset,
        })
        .collect::<Vec<_>>();

    let mut sources: BTreeMap<String, Vec<CompileUnitSummary>> = BTreeMap::new();
    for cu in &summaries {
        let key: String = cu
            .name
            .clone()
            .unwrap_or_else(|| format!("<cu@{:#x}>", cu.unit_offset));
        sources.entry(key).or_default().push(cu.clone());
    }

    WasmDwarfRecovery {
        sources,
        functions: symbols.functions,
        line_map: lines.entries,
        types,
        compile_units: summaries,
        section_bytes,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::dwarf::lines::SourceLocation;

    #[test]
    fn empty_recovery_round_trips_json() {
        let recovery: WasmDwarfRecovery = WasmDwarfRecovery::default();
        let json: serde_json::Value = recovery.to_sourcemap_json();
        assert_eq!(json["version"], 1);
        assert_eq!(json["function_count"], 0);
    }

    #[test]
    fn resolve_pc_falls_back_to_floor_entry() {
        let mut recovery: WasmDwarfRecovery = WasmDwarfRecovery::default();
        recovery.line_map.insert(
            0x10,
            SourceLocation {
                file: "a.c".into(),
                line: 5,
                column: 0,
            },
        );
        let resolved: &SourceLocation = recovery.resolve_pc(0x14).unwrap();
        assert_eq!(resolved.line, 5);
    }
}
