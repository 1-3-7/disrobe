use std::collections::BTreeMap;

use serde::Serialize;
use wasmparser::{MemoryType, Parser, Payload};

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
    pub uses_memory64: bool,
    pub multi_memory: bool,
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
    if input.len() < 8 || &input[..4] != b"\0asm" {
        return Err(Error::Parse(
            "DR-WASMDEOB-MEM64: not a wasm module".to_owned(),
        ));
    }
    let mut report: MemoryReport = MemoryReport::default();
    let mut idx: u32 = 0u32;
    for payload in Parser::new(0).parse_all(input) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(format!("{e}")))?;
        if let Payload::MemorySection(reader) = payload {
            for mem in reader {
                let mem: MemoryType = mem.map_err(|e| Error::Parse(format!("{e}")))?;
                if mem.memory64 {
                    report.uses_memory64 = true;
                }
                report.memories.insert(
                    idx,
                    MemoryRecord {
                        index: idx,
                        memory64: mem.memory64,
                        shared: mem.shared,
                        initial: mem.initial,
                        maximum: mem.maximum,
                        page_size_log2: mem.page_size_log2,
                    },
                );
                idx = idx.saturating_add(1);
            }
        }
    }
    report.multi_memory = report.memory_count() > 1;
    Ok(report)
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
}
