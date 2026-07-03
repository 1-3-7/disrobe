use serde::Serialize;
use wasmparser::{Parser, Payload};

use crate::debug::{dbg_kv, dbg_line, dbg_section};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NameInfo {
    pub module_name: Option<String>,
    pub function_count: usize,
    pub function_names: Vec<(u32, String)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ModuleSummary {
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub names: NameInfo,
    pub type_count: usize,
    pub func_count: usize,
    pub table_count: usize,
    pub memory_count: usize,
    pub global_count: usize,
    pub data_segments: usize,
    pub element_segments: usize,
    pub code_size_bytes: u64,
    pub has_dwarf: bool,
    pub dwarf_section_count: usize,
}

pub fn analyze_module(input: &[u8]) -> Result<ModuleSummary> {
    dbg_section("module-parse");
    dbg_kv("input-len", || input.len().to_string());
    let mut summary: ModuleSummary = ModuleSummary::default();
    for payload in Parser::new(0).parse_all(input) {
        let payload: Payload<'_> = payload.map_err(|e| {
            dbg_line(|| format!("parse-error: {e}"));
            Error::Parse(format!("{e}"))
        })?;
        match payload {
            Payload::TypeSection(reader) => {
                summary.type_count = reader.count() as usize;
            }
            Payload::FunctionSection(reader) => {
                summary.func_count = reader.count() as usize;
            }
            Payload::TableSection(reader) => {
                summary.table_count = reader.count() as usize;
            }
            Payload::MemorySection(reader) => {
                summary.memory_count = reader.count() as usize;
            }
            Payload::GlobalSection(reader) => {
                summary.global_count = reader.count() as usize;
            }
            Payload::ImportSection(reader) => {
                for imp in reader.into_imports() {
                    let import: wasmparser::Import<'_> =
                        imp.map_err(|e| Error::Parse(format!("{e}")))?;
                    summary
                        .imports
                        .push(format!("{}::{}", import.module, import.name));
                }
            }
            Payload::ExportSection(reader) => {
                for exp in reader {
                    let export: wasmparser::Export<'_> =
                        exp.map_err(|e| Error::Parse(format!("{e}")))?;
                    summary.exports.push(export.name.to_owned());
                }
            }
            Payload::DataSection(reader) => {
                summary.data_segments = reader.count() as usize;
            }
            Payload::ElementSection(reader) => {
                summary.element_segments = reader.count() as usize;
            }
            Payload::CodeSectionEntry(body) => {
                let range: core::ops::Range<usize> = body.range();
                summary.code_size_bytes += (range.end - range.start) as u64;
            }
            Payload::CustomSection(reader) => {
                let name: &str = reader.name();
                if matches!(
                    name,
                    ".debug_info"
                        | ".debug_abbrev"
                        | ".debug_line"
                        | ".debug_str"
                        | ".debug_str_offsets"
                        | ".debug_line_str"
                        | ".debug_ranges"
                        | ".debug_rnglists"
                        | ".debug_pubnames"
                        | ".debug_pubtypes"
                        | ".debug_addr"
                        | ".debug_loc"
                        | ".debug_loclists"
                        | ".debug_aranges"
                ) {
                    summary.has_dwarf = true;
                    summary.dwarf_section_count += 1;
                }
            }
            _ => {}
        }
    }
    dbg_kv("module-shape", || {
        format!(
            "types={} funcs={} tables={} memories={} globals={} data={} elems={}",
            summary.type_count,
            summary.func_count,
            summary.table_count,
            summary.memory_count,
            summary.global_count,
            summary.data_segments,
            summary.element_segments
        )
    });
    dbg_kv("import-export", || {
        format!(
            "imports={} exports={}",
            summary.imports.len(),
            summary.exports.len()
        )
    });
    dbg_kv("code-size-bytes", || summary.code_size_bytes.to_string());
    dbg_kv("dwarf-sections", || {
        format!(
            "has_dwarf={} section_count={}",
            summary.has_dwarf, summary.dwarf_section_count
        )
    });
    Ok(summary)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const EMPTY_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    #[test]
    fn parses_empty_module() {
        let summary: ModuleSummary = analyze_module(EMPTY_WASM).unwrap();
        assert_eq!(summary.type_count, 0);
        assert_eq!(summary.func_count, 0);
        assert!(summary.imports.is_empty());
        assert!(summary.exports.is_empty());
    }

    #[test]
    fn rejects_garbage() {
        let err: Error = analyze_module(b"not wasm").unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }
}
