#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_wasm_deob::{MemoryRecord, MemoryReport, scan_memories};

const MEM64_WAT: &str = "(module (memory $m i64 1))";

#[test]
fn memory64_module_yields_u64_index_typed_lift() {
    let bytes: Vec<u8> = wat::parse_str(MEM64_WAT).expect("parse wat");
    let report: MemoryReport = scan_memories(&bytes).expect("scan");
    assert!(report.uses_memory64);
    let mem: &MemoryRecord = report.memories.get(&0).expect("mem0");
    assert_eq!(mem.index_type(), "u64");
    let decl: String = report.rust_static_slices();
    assert!(decl.contains("MEMORY_0"));
    assert!(decl.contains("index-as-u64"));
}
