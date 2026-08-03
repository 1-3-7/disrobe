#![allow(clippy::expect_used, clippy::unwrap_used)]
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_wasm_deob::{AtomicOpKind, AtomicOpRecord, ThreadsReport, scan_threads};

const ATOMIC_RMW: &str = r#"
    (module
      (memory $m 1 1 shared)
      (func (export "inc") (param i32) (result i32)
        local.get 0
        i32.const 1
        i32.atomic.rmw.add offset=0 align=4))
"#;

const ATOMIC_RMW_OPERATIONS: &str = r#"
    (module
      (memory $m 1 1 shared)
      (func (export "add") (param i32 i32) (result i32)
        local.get 0 local.get 1 i32.atomic.rmw.add offset=4 align=4)
      (func (export "sub") (param i32 i32) (result i32)
        local.get 0 local.get 1 i32.atomic.rmw.sub offset=4 align=4)
      (func (export "and") (param i32 i32) (result i32)
        local.get 0 local.get 1 i32.atomic.rmw.and offset=4 align=4)
      (func (export "or") (param i32 i32) (result i32)
        local.get 0 local.get 1 i32.atomic.rmw.or offset=4 align=4)
      (func (export "xor") (param i32 i32) (result i32)
        local.get 0 local.get 1 i32.atomic.rmw.xor offset=4 align=4)
      (func (export "xchg") (param i32 i32) (result i32)
        local.get 0 local.get 1 i32.atomic.rmw.xchg offset=4 align=4))
"#;

const ATOMIC_SCALAR_OPERATIONS: &str = r#"
    (module
      (memory $m 1 1 shared)
      (func (export "load") (param i32) (result i32)
        local.get 0 i32.atomic.load offset=4 align=4)
      (func (export "store") (param i32 i32)
        local.get 0 local.get 1 i32.atomic.store offset=4 align=4)
      (func (export "cmpxchg") (param i32 i32 i32) (result i32)
        local.get 0 local.get 1 local.get 2 i32.atomic.rmw.cmpxchg offset=4 align=4))
"#;

const ATOMIC_NARROW_OPERATIONS: &str = r#"
    (module
      (memory $m 1 1 shared)
      (func (export "i32_load8") (param i32) (result i32)
        local.get 0 i32.atomic.load8_u align=1)
      (func (export "i32_load16") (param i32) (result i32)
        local.get 0 i32.atomic.load16_u align=2)
      (func (export "i64_load8") (param i32) (result i64)
        local.get 0 i64.atomic.load8_u align=1)
      (func (export "i64_load16") (param i32) (result i64)
        local.get 0 i64.atomic.load16_u align=2)
      (func (export "i64_load32") (param i32) (result i64)
        local.get 0 i64.atomic.load32_u align=4)
      (func (export "i32_store8") (param i32 i32)
        local.get 0 local.get 1 i32.atomic.store8 align=1)
      (func (export "i32_store16") (param i32 i32)
        local.get 0 local.get 1 i32.atomic.store16 align=2)
      (func (export "i64_store8") (param i32 i64)
        local.get 0 local.get 1 i64.atomic.store8 align=1)
      (func (export "i64_store16") (param i32 i64)
        local.get 0 local.get 1 i64.atomic.store16 align=2)
      (func (export "i64_store32") (param i32 i64)
        local.get 0 local.get 1 i64.atomic.store32 align=4))
"#;

fn compile_and_run_atomic_lifts(source: &str) {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("wasm_atomic_rust_lift").expect("scratch");
    let source_path: PathBuf = scratch.path().join("atomic_lift.rs");
    let executable_path: PathBuf = scratch.path().join(if cfg!(windows) {
        "atomic_lift.exe"
    } else {
        "atomic_lift"
    });
    std::fs::write(&source_path, source).expect("write source file");
    let compile: std::process::Output = Command::new("rustc")
        .args(["--edition", "2024", "-o"])
        .arg(&executable_path)
        .arg(&source_path)
        .output()
        .expect("rustc must be available for the Rust lift gate");
    assert!(
        compile.status.success(),
        "rustc rejected atomic Rust lifts\n{}\n{source}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let run: std::process::Output = Command::new(&executable_path)
        .output()
        .expect("run compiled atomic lift");
    assert!(
        run.status.success(),
        "atomic Rust lifts produced wrong values\n{}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn shared_memory_and_atomic_rmw_observed_and_lifted() {
    let bytes: Vec<u8> = wat::parse_str(ATOMIC_RMW).expect("parse wat");
    let report: ThreadsReport = scan_threads(&bytes).expect("scan");
    assert!(!report.is_empty());
    assert_eq!(report.shared_memories.len(), 1);
    let rmw: &AtomicOpRecord = report
        .atomic_ops
        .iter()
        .find(|o: &&AtomicOpRecord| matches!(o.kind, AtomicOpKind::Rmw))
        .expect("rmw present");
    assert!(rmw.rust_lift.contains("AtomicI32"));
    assert!(rmw.rust_lift.contains("SeqCst"));
}

#[test]
fn atomic_fence_lifts_to_std_sync_atomic_fence() {
    let wat: &str = r#"(module (func (export "f") atomic.fence))"#;
    let bytes: Vec<u8> = wat::parse_str(wat).expect("parse");
    let report: ThreadsReport = scan_threads(&bytes).expect("scan");
    assert!(report.uses_atomic_fence);
    assert!(
        report
            .atomic_ops
            .iter()
            .any(|o: &AtomicOpRecord| o.rust_lift.contains("fence("))
    );
}

#[test]
fn atomic_rmw_rust_lifts_execute_declared_operations() {
    let bytes: Vec<u8> = wat::parse_str(ATOMIC_RMW_OPERATIONS).expect("parse wat");
    let report: ThreadsReport = scan_threads(&bytes).expect("scan");
    let cases: [(&str, i32, i32, i32); 6] = [
        ("i32.atomic.rmw.add", 12, 5, 17),
        ("i32.atomic.rmw.sub", 12, 5, 7),
        ("i32.atomic.rmw.and", 12, 10, 8),
        ("i32.atomic.rmw.or", 12, 10, 14),
        ("i32.atomic.rmw.xor", 12, 10, 6),
        ("i32.atomic.rmw.xchg", 12, 5, 5),
    ];
    let mut source: String = String::from("fn main() {\n");
    for (mnemonic, initial, value, expected) in cases {
        let op: &AtomicOpRecord = report
            .atomic_ops
            .iter()
            .find(|op: &&AtomicOpRecord| op.mnemonic == mnemonic)
            .expect("RMW operation present");
        writeln!(
            &mut source,
            "{{ let cells: [std::sync::atomic::AtomicI32; 2] = [std::sync::atomic::AtomicI32::new(99), std::sync::atomic::AtomicI32::new({initial})]; let ptr: *const u8 = cells.as_ptr() as *const u8; let val: i32 = {value}; let before: i32 = {}; assert_eq!(before, {initial}); assert_eq!(cells[0].load(std::sync::atomic::Ordering::SeqCst), 99); assert_eq!(cells[1].load(std::sync::atomic::Ordering::SeqCst), {expected}); }}",
            op.rust_lift
        )
        .expect("write source");
    }
    source.push_str("}\n");
    compile_and_run_atomic_lifts(&source);
}

#[test]
fn atomic_scalar_rust_lifts_execute() {
    let bytes: Vec<u8> = wat::parse_str(ATOMIC_SCALAR_OPERATIONS).expect("parse wat");
    let report: ThreadsReport = scan_threads(&bytes).expect("scan");
    let load: &AtomicOpRecord = report
        .atomic_ops
        .iter()
        .find(|op: &&AtomicOpRecord| op.mnemonic == "i32.atomic.load")
        .expect("load present");
    let store: &AtomicOpRecord = report
        .atomic_ops
        .iter()
        .find(|op: &&AtomicOpRecord| op.mnemonic == "i32.atomic.store")
        .expect("store present");
    let cmpxchg: &AtomicOpRecord = report
        .atomic_ops
        .iter()
        .find(|op: &&AtomicOpRecord| op.mnemonic == "i32.atomic.rmw.cmpxchg")
        .expect("cmpxchg present");
    let mut source: String = String::from("fn main() {\n");
    writeln!(
        &mut source,
        "{{ let cells: [std::sync::atomic::AtomicI32; 2] = [std::sync::atomic::AtomicI32::new(99), std::sync::atomic::AtomicI32::new(12)]; let ptr: *const u8 = cells.as_ptr() as *const u8; let observed: i32 = {}; assert_eq!(observed, 12); assert_eq!(cells[0].load(std::sync::atomic::Ordering::SeqCst), 99); }}",
        load.rust_lift
    )
    .expect("write load source");
    writeln!(
        &mut source,
        "{{ let cells: [std::sync::atomic::AtomicI32; 2] = [std::sync::atomic::AtomicI32::new(99), std::sync::atomic::AtomicI32::new(12)]; let ptr: *const u8 = cells.as_ptr() as *const u8; let val: i32 = 5; {}; assert_eq!(cells[0].load(std::sync::atomic::Ordering::SeqCst), 99); assert_eq!(cells[1].load(std::sync::atomic::Ordering::SeqCst), 5); }}",
        store.rust_lift
    )
    .expect("write store source");
    writeln!(
        &mut source,
        "{{ let cells: [std::sync::atomic::AtomicI32; 2] = [std::sync::atomic::AtomicI32::new(99), std::sync::atomic::AtomicI32::new(12)]; let ptr: *const u8 = cells.as_ptr() as *const u8; let old: i32 = 12; let new: i32 = 5; let observed: i32 = {}; assert_eq!(observed, 12); assert_eq!(cells[0].load(std::sync::atomic::Ordering::SeqCst), 99); assert_eq!(cells[1].load(std::sync::atomic::Ordering::SeqCst), 5); }}",
        cmpxchg.rust_lift
    )
    .expect("write successful cmpxchg source");
    writeln!(
        &mut source,
        "{{ let cells: [std::sync::atomic::AtomicI32; 2] = [std::sync::atomic::AtomicI32::new(99), std::sync::atomic::AtomicI32::new(12)]; let ptr: *const u8 = cells.as_ptr() as *const u8; let old: i32 = 7; let new: i32 = 5; let observed: i32 = {}; assert_eq!(observed, 12); assert_eq!(cells[0].load(std::sync::atomic::Ordering::SeqCst), 99); assert_eq!(cells[1].load(std::sync::atomic::Ordering::SeqCst), 12); }}",
        cmpxchg.rust_lift
    )
    .expect("write failed cmpxchg source");
    source.push_str("}\n");
    compile_and_run_atomic_lifts(&source);
}

#[test]
fn narrow_atomic_load_rust_lifts_zero_extend() {
    let bytes: Vec<u8> = wat::parse_str(ATOMIC_NARROW_OPERATIONS).expect("parse wat");
    let report: ThreadsReport = scan_threads(&bytes).expect("scan");
    let cases: [(&str, &str, &str); 5] = [
        ("i32.atomic.load8_u", "i32", "239"),
        ("i32.atomic.load16_u", "i32", "52719"),
        ("i64.atomic.load8_u", "i64", "239"),
        ("i64.atomic.load16_u", "i64", "52719"),
        ("i64.atomic.load32_u", "i64", "2309737967"),
    ];
    let mut source: String = String::from("fn main() {\n");
    for (mnemonic, result_type, expected) in cases {
        let op: &AtomicOpRecord = report
            .atomic_ops
            .iter()
            .find(|op: &&AtomicOpRecord| op.mnemonic == mnemonic)
            .expect("narrow load present");
        writeln!(
            &mut source,
            "{{ let backing: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0x1122_3344_89ab_cdef); let ptr: *const u8 = &backing as *const std::sync::atomic::AtomicU64 as *const u8; let observed: {result_type} = {}; assert_eq!(observed, {expected}); }}",
            op.rust_lift
        )
        .expect("write narrow load source");
    }
    source.push_str("}\n");
    compile_and_run_atomic_lifts(&source);
}

#[test]
fn narrow_atomic_store_rust_lifts_truncate() {
    let bytes: Vec<u8> = wat::parse_str(ATOMIC_NARROW_OPERATIONS).expect("parse wat");
    let report: ThreadsReport = scan_threads(&bytes).expect("scan");
    let cases: [(&str, &str, &str, &str); 5] = [
        ("i32.atomic.store8", "i32", "4660", "0xffff_ffff_0000_0034"),
        (
            "i32.atomic.store16",
            "i32",
            "305419896",
            "0xffff_ffff_0000_5678",
        ),
        ("i64.atomic.store8", "i64", "4660", "0xffff_ffff_0000_0034"),
        (
            "i64.atomic.store16",
            "i64",
            "305419896",
            "0xffff_ffff_0000_5678",
        ),
        (
            "i64.atomic.store32",
            "i64",
            "1311768467463790320",
            "0xffff_ffff_9abc_def0",
        ),
    ];
    let mut source: String = String::from("fn main() {\n");
    for (mnemonic, value_type, value, expected) in cases {
        let op: &AtomicOpRecord = report
            .atomic_ops
            .iter()
            .find(|op: &&AtomicOpRecord| op.mnemonic == mnemonic)
            .expect("narrow store present");
        writeln!(
            &mut source,
            "{{ let backing: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0xffff_ffff_0000_0000); let ptr: *const u8 = &backing as *const std::sync::atomic::AtomicU64 as *const u8; let val: {value_type} = {value}; {}; assert_eq!(backing.load(std::sync::atomic::Ordering::SeqCst), {expected}); }}",
            op.rust_lift
        )
        .expect("write narrow store source");
    }
    source.push_str("}\n");
    compile_and_run_atomic_lifts(&source);
}
