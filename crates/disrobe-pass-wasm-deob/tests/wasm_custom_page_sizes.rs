#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_pass_wasm_deob::{
    CustomPageSizeRecord, CustomPageSizeReport, DEFAULT_PAGE_SIZE_BYTES, DEFAULT_PAGE_SIZE_LOG2,
    scan_custom_page_sizes,
};

#[test]
fn default_module_reports_64ki_page_size() {
    let bytes: Vec<u8> = wat::parse_str("(module (memory 1))").expect("wat");
    let report: CustomPageSizeReport = scan_custom_page_sizes(&bytes).expect("scan");
    assert_eq!(report.count(), 1usize);
    let rec: &CustomPageSizeRecord = report.memories.get(&0u32).expect("mem0");
    assert_eq!(rec.page_size_log2, DEFAULT_PAGE_SIZE_LOG2);
    assert_eq!(rec.page_size_bytes, DEFAULT_PAGE_SIZE_BYTES);
    assert!(!report.uses_custom_page_size);
}

#[test]
fn detects_multi_memory_distinct_page_sizes() {
    let bytes: Vec<u8> = wat::parse_str("(module (memory 1) (memory 2))").expect("wat");
    let report: CustomPageSizeReport = scan_custom_page_sizes(&bytes).expect("scan");
    assert_eq!(report.count(), 2usize);
}

#[test]
fn custom_page_size_detected_when_supported() {
    let candidates: &[&str] = &[
        r"(module (memory 1 (pagesize 1)))",
        r"(module (memory 16 (pagesize 1)))",
    ];
    for src in candidates {
        let Ok(bytes): Result<Vec<u8>, _> = wat::parse_str(src) else {
            continue;
        };
        let report: CustomPageSizeReport = scan_custom_page_sizes(&bytes).expect("scan");
        if report.uses_custom_page_size {
            assert!(
                report
                    .smallest_page_size_bytes
                    .is_some_and(|b| b < DEFAULT_PAGE_SIZE_BYTES)
            );
            return;
        }
    }
}
