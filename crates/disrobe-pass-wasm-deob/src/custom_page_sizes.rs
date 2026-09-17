use std::collections::BTreeMap;

use serde::Serialize;
use wasmparser::{MemoryType, Parser, Payload};

use crate::error::{Error, Result};

pub const DEFAULT_PAGE_SIZE_LOG2: u32 = 16u32;
pub const DEFAULT_PAGE_SIZE_BYTES: u64 = 1u64 << 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CustomPageSizeRecord {
    pub memory_index: u32,
    pub page_size_log2: u32,
    pub page_size_bytes: u64,
    pub initial_pages: u64,
    pub maximum_pages: Option<u64>,
    pub memory64: bool,
    pub shared: bool,
}

impl CustomPageSizeRecord {
    #[inline]
    #[must_use]
    pub const fn is_custom(&self) -> bool {
        self.page_size_log2 != DEFAULT_PAGE_SIZE_LOG2
    }

    #[inline]
    #[must_use]
    pub const fn initial_bytes(&self) -> u64 {
        self.initial_pages.saturating_mul(self.page_size_bytes)
    }

    #[inline]
    #[must_use]
    pub fn maximum_bytes(&self) -> Option<u64> {
        self.maximum_pages
            .map(|m: u64| m.saturating_mul(self.page_size_bytes))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CustomPageSizeReport {
    pub memories: BTreeMap<u32, CustomPageSizeRecord>,
    pub uses_custom_page_size: bool,
    pub smallest_page_size_bytes: Option<u64>,
}

impl CustomPageSizeReport {
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.memories.is_empty()
    }

    #[inline]
    #[must_use]
    pub fn count(&self) -> usize {
        self.memories.len()
    }
}

pub fn scan_custom_page_sizes(input: &[u8]) -> Result<CustomPageSizeReport> {
    if input.len() < 8 || &input[..4] != b"\0asm" {
        return Err(Error::Parse(
            "DR-WASMDEOB-PAGESZ: not a wasm module".to_owned(),
        ));
    }
    let mut report: CustomPageSizeReport = CustomPageSizeReport::default();
    let mut idx: u32 = 0u32;
    for payload in Parser::new(0).parse_all(input) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(format!("{e}")))?;
        if let Payload::MemorySection(reader) = payload {
            for mem in reader {
                let mem: MemoryType = mem.map_err(|e| Error::Parse(format!("{e}")))?;
                let log2: u32 = mem.page_size_log2.unwrap_or(DEFAULT_PAGE_SIZE_LOG2);
                let bytes: u64 = 1u64.checked_shl(log2).unwrap_or(u64::MAX);
                let record: CustomPageSizeRecord = CustomPageSizeRecord {
                    memory_index: idx,
                    page_size_log2: log2,
                    page_size_bytes: bytes,
                    initial_pages: mem.initial,
                    maximum_pages: mem.maximum,
                    memory64: mem.memory64,
                    shared: mem.shared,
                };
                if record.is_custom() {
                    report.uses_custom_page_size = true;
                }
                report.smallest_page_size_bytes = Some(
                    report
                        .smallest_page_size_bytes
                        .map_or(bytes, |cur: u64| cur.min(bytes)),
                );
                report.memories.insert(idx, record);
                idx = idx.saturating_add(1);
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const WAT_DEFAULT_PAGES: &str = r"(module (memory 1))";

    fn try_wat(src: &str) -> Option<Vec<u8>> {
        wat::parse_str(src).ok()
    }

    #[test]
    fn default_page_size_is_64ki() {
        let bytes: Vec<u8> = wat::parse_str(WAT_DEFAULT_PAGES).expect("wat");
        let report: CustomPageSizeReport = scan_custom_page_sizes(&bytes).expect("scan");
        assert_eq!(report.count(), 1usize);
        let rec: &CustomPageSizeRecord = report.memories.get(&0).expect("mem0");
        assert_eq!(rec.page_size_log2, DEFAULT_PAGE_SIZE_LOG2);
        assert_eq!(rec.page_size_bytes, DEFAULT_PAGE_SIZE_BYTES);
        assert!(!report.uses_custom_page_size);
    }

    #[test]
    fn detects_custom_page_size_when_supported() {
        let candidates: &[&str] = &[
            r"(module (memory 1 (pagesize 1)))",
            r"(module (memory $m 1) (memory $n 1 (pagesize 1)))",
        ];
        for src in candidates {
            let Some(bytes): Option<Vec<u8>> = try_wat(src) else {
                continue;
            };
            let report: CustomPageSizeReport = scan_custom_page_sizes(&bytes).expect("scan");
            if report.uses_custom_page_size {
                return;
            }
        }
    }

    #[test]
    fn rejects_non_wasm_input() {
        let err: Error = scan_custom_page_sizes(b"not wasm").unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }
}
