#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftResult, LiftTarget, MemoryRecord, MemoryReport, ModuleSignatures,
    extract_signatures, lift_function_body, scan_memories,
};
use wasmparser::{FunctionBody, Parser, Payload};

const MEM64_WAT: &str = "(module (memory $m i64 1))";

const MEM64_ACCESSORS: &str = r#"
(module
  (memory $m i64 1 16)
  (func $read (export "read") (param $offset i64) (result i32)
    local.get $offset
    i32.load8_u)
  (func $write (export "write") (param $offset i64) (param $value i32)
    local.get $offset
    local.get $value
    i32.store8)
  (func $size (export "size") (result i64)
    memory.size))
"#;

fn defined_bodies(bytes: &[u8]) -> Vec<FunctionBody<'_>> {
    let mut out: Vec<FunctionBody<'_>> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            out.push(body);
        }
    }
    out
}

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

#[test]
fn per_function_lift_of_memory64_body_reassembles_with_i64_memory() {
    let bytes: Vec<u8> = wat::parse_str(MEM64_ACCESSORS).expect("parse accessors");
    let sigs: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    let defined: &[FunctionSig] = sigs.defined();
    let callees: CalleeNames = CalleeNames::new(sigs.callee_names());
    let bodies: Vec<FunctionBody<'_>> = defined_bodies(&bytes);
    assert_eq!(bodies.len(), 3, "read/write/size");

    for (idx, expect_i64_prefix) in [(0usize, true), (1usize, true), (2usize, true)] {
        let lifted: LiftResult =
            lift_function_body(&bodies[idx], &defined[idx], &callees, LiftTarget::Wat);
        let reparsed: Result<Vec<u8>, wat::Error> = wat::parse_str(&lifted.pseudo_source);
        assert!(
            reparsed.is_ok(),
            "memory64 function {} must lift to reassemblable WAT (was invalid before i64 memory tracking):\n{}\nerror: {:?}",
            defined[idx].name,
            lifted.pseudo_source,
            reparsed.err()
        );
        if expect_i64_prefix {
            assert!(
                lifted.pseudo_source.contains("(memory $m0 i64"),
                "function {} touches a 64-bit memory, so the emitted memory must carry the i64 index type:\n{}",
                defined[idx].name,
                lifted.pseudo_source
            );
        }
    }
}
