#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_wasm_deob::{MemoryReport, scan_memories};

const MULTI_WAT: &str = r"
    (module
      (memory $m0 1)
      (memory $m1 1))
";

#[test]
fn multi_memory_yields_distinct_static_slices() {
    let bytes: Vec<u8> = wat::parse_str(MULTI_WAT).expect("parse wat");
    let report: MemoryReport = scan_memories(&bytes).expect("scan");
    assert!(report.multi_memory);
    assert_eq!(report.memory_count(), 2);
    let decl: String = report.rust_static_slices();
    assert!(decl.contains("MEMORY_0"));
    assert!(decl.contains("MEMORY_1"));
}
