use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use wasmparser::{MemoryType, Operator, Parser, Payload, TypeRef};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MemoryRecord {
    pub index: u32,
    pub memory64: bool,
    pub shared: bool,
    pub initial: u64,
    pub maximum: Option<u64>,
    pub page_size_log2: Option<u32>,
}

impl MemoryRecord {
    #[inline]
    #[must_use]
    pub const fn index_type(&self) -> &'static str {
        if self.memory64 { "u64" } else { "u32" }
    }

    #[inline]
    #[must_use]
    pub fn rust_static_slice_decl(&self) -> String {
        let size_unit: &str = if self.memory64 { "u64" } else { "u32" };
        format!(
            "static mut MEMORY_{idx}: Vec<u8> = Vec::new(); /* index-as-{size_unit}, initial_pages={initial}, max={max:?}, shared={shared} */",
            idx = self.index,
            initial = self.initial,
            max = self.maximum,
            shared = self.shared,
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MemoryReport {
    pub memories: BTreeMap<u32, MemoryRecord>,
    pub memory_grows: BTreeSet<u32>,
    pub uses_memory64: bool,
    pub multi_memory: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ModuleMemoryScan {
    pub(crate) report: MemoryReport,
    pub(crate) function_body_ranges: Vec<(usize, usize)>,
    pub(crate) imported_memories: BTreeSet<u32>,
    pub(crate) import_count: u32,
    pub(crate) data_segment_count: u32,
    pub(crate) global_count: u32,
    pub(crate) tag_count: u32,
    pub(crate) table_count: u32,
    pub(crate) element_segment_count: u32,
    pub(crate) start_function: Option<u32>,
    pub(crate) memory_grow_scan_error: Option<String>,
}

impl MemoryReport {
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.memories.is_empty()
    }

    #[inline]
    #[must_use]
    pub fn memory_count(&self) -> usize {
        self.memories.len()
    }

    #[must_use]
    pub fn rust_static_slices(&self) -> String {
        let mut out: String = String::with_capacity(self.memories.len() * 64);
        for rec in self.memories.values() {
            out.push_str(&rec.rust_static_slice_decl());
            out.push('\n');
        }
        out
    }
}

pub fn scan_memories(input: &[u8]) -> Result<MemoryReport> {
    let scan: ModuleMemoryScan = scan_module_memories(input)?;
    if let Some(error) = scan.memory_grow_scan_error {
        return Err(Error::Parse(error));
    }
    Ok(scan.report)
}

pub(crate) fn scan_module_memories(input: &[u8]) -> Result<ModuleMemoryScan> {
    if input.len() < 8 || &input[..4] != b"\0asm" {
        return Err(Error::Parse(
            "DR-WASMDEOB-MEM64: not a wasm module".to_owned(),
        ));
    }
    let mut scan: ModuleMemoryScan = ModuleMemoryScan::default();
    let mut idx: u32 = 0u32;
    for payload in Parser::new(0).parse_all(input) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(format!("{e}")))?;
        match payload {
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import: wasmparser::Import<'_> =
                        import.map_err(|e| Error::Parse(format!("{e}")))?;
                    scan.import_count = scan.import_count.saturating_add(1);
                    match import.ty {
                        TypeRef::Memory(mem) => {
                            let memory_index: u32 = idx;
                            record_memory(&mut scan.report, &mut idx, mem);
                            scan.imported_memories.insert(memory_index);
                        }
                        TypeRef::Global(_) => {
                            scan.global_count = scan.global_count.saturating_add(1);
                        }
                        _ => {}
                    }
                }
            }
            Payload::MemorySection(reader) => {
                for mem in reader {
                    let mem: MemoryType = mem.map_err(|e| Error::Parse(format!("{e}")))?;
                    record_memory(&mut scan.report, &mut idx, mem);
                }
            }
            Payload::TableSection(reader) => {
                for table in reader {
                    let _: wasmparser::Table<'_> =
                        table.map_err(|e| Error::Parse(format!("{e}")))?;
                    scan.table_count = scan.table_count.saturating_add(1);
                }
            }
            Payload::GlobalSection(reader) => {
                for global in reader {
                    let _: wasmparser::Global<'_> =
                        global.map_err(|e| Error::Parse(format!("{e}")))?;
                    scan.global_count = scan.global_count.saturating_add(1);
                }
            }
            Payload::TagSection(reader) => {
                for tag in reader {
                    let _: wasmparser::TagType = tag.map_err(|e| Error::Parse(format!("{e}")))?;
                    scan.tag_count = scan.tag_count.saturating_add(1);
                }
            }
            Payload::CodeSectionEntry(body) => {
                let range: std::ops::Range<usize> = body.range();
                scan.function_body_ranges.push((range.start, range.end));
                match body.get_operators_reader() {
                    Ok(reader) => {
                        for op in reader {
                            match op {
                                Ok(Operator::MemoryGrow { mem }) => {
                                    scan.report.memory_grows.insert(mem);
                                }
                                Ok(_) => {}
                                Err(error) => {
                                    if scan.memory_grow_scan_error.is_none() {
                                        scan.memory_grow_scan_error = Some(format!("{error}"));
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    Err(error) => {
                        if scan.memory_grow_scan_error.is_none() {
                            scan.memory_grow_scan_error = Some(format!("{error}"));
                        }
                    }
                }
            }
            Payload::ElementSection(reader) => {
                for element in reader {
                    let _: wasmparser::Element<'_> =
                        element.map_err(|e| Error::Parse(format!("{e}")))?;
                    scan.element_segment_count = scan.element_segment_count.saturating_add(1);
                }
            }
            Payload::DataSection(reader) => {
                for data in reader {
                    let _: wasmparser::Data<'_> = data.map_err(|e| Error::Parse(format!("{e}")))?;
                    scan.data_segment_count = scan.data_segment_count.saturating_add(1);
                }
            }
            Payload::StartSection { func, .. } => {
                scan.start_function = Some(func);
            }
            _ => {}
        }
    }
    scan.report.multi_memory = scan.report.memory_count() > 1;
    Ok(scan)
}

fn record_memory(report: &mut MemoryReport, idx: &mut u32, mem: MemoryType) {
    if mem.memory64 {
        report.uses_memory64 = true;
    }
    report.memories.insert(
        *idx,
        MemoryRecord {
            index: *idx,
            memory64: mem.memory64,
            shared: mem.shared,
            initial: mem.initial,
            maximum: mem.maximum,
            page_size_log2: mem.page_size_log2,
        },
    );
    *idx = idx.saturating_add(1);
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const MEM64_WAT: &str = r"
        (module
          (memory $m i64 1))
    ";

    const MULTI_MEM_WAT: &str = r"
        (module
          (memory $m0 1)
          (memory $m1 1))
    ";

    const IMPORTED_AND_DEFINED_MEMORIES_WAT: &str = r#"
        (module
          (import "env" "noop" (func $noop))
          (import "env" "memory" (memory i64 2 4 shared))
          (memory 3))
    "#;

    #[test]
    fn detects_memory64_and_emits_u64_index_type() {
        let bytes: Vec<u8> = wat::parse_str(MEM64_WAT).expect("wat");
        let report: MemoryReport = scan_memories(&bytes).expect("scan");
        assert!(report.uses_memory64);
        let mem: &MemoryRecord = report.memories.get(&0).expect("mem0");
        assert!(mem.memory64);
        assert_eq!(mem.index_type(), "u64");
        let decl: String = report.rust_static_slices();
        assert!(decl.contains("MEMORY_0"));
        assert!(decl.contains("index-as-u64"));
    }

    #[test]
    fn detects_multi_memory_and_emits_distinct_statics() {
        let bytes: Vec<u8> = wat::parse_str(MULTI_MEM_WAT).expect("wat");
        let report: MemoryReport = scan_memories(&bytes).expect("scan");
        assert!(report.multi_memory);
        assert_eq!(report.memory_count(), 2);
        let decl: String = report.rust_static_slices();
        assert!(decl.contains("MEMORY_0"));
        assert!(decl.contains("MEMORY_1"));
    }

    #[test]
    fn indexes_imported_memory64_before_defined_memories() {
        let bytes: Vec<u8> = wat::parse_str(IMPORTED_AND_DEFINED_MEMORIES_WAT).expect("wat");
        let report: MemoryReport = scan_memories(&bytes).expect("scan");
        let imported: &MemoryRecord = report.memories.get(&0).expect("imported memory");
        let defined: &MemoryRecord = report.memories.get(&1).expect("defined memory");
        assert!(report.uses_memory64);
        assert!(report.multi_memory);
        assert_eq!(report.memory_count(), 2);
        assert!(imported.memory64);
        assert!(imported.shared);
        assert_eq!(imported.initial, 2);
        assert_eq!(imported.maximum, Some(4));
        assert!(!defined.memory64);
        assert!(!defined.shared);
        assert_eq!(defined.initial, 3);
        assert_eq!(defined.maximum, None);
    }
}
