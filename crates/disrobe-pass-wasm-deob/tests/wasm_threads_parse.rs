#![allow(clippy::expect_used, clippy::unwrap_used)]
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_wasm_deob::{
    AtomicOpKind, AtomicOpRecord, SharedMemoryRecord, ThreadsReport, scan_threads,
};

const ATOMIC_RMW: &str = r#"
    (module
      (memory $m 1 1 shared)
      (func (export "inc") (param i32) (result i32)
        local.get 0
        i32.const 1
        i32.atomic.rmw.add offset=0 align=4))
"#;

const IMPORTED_SHARED_MEMORIES: &str = r#"
    (module
      (import "env" "plain" (memory 1))
      (import "env" "helper" (func))
      (import "env" "shared" (memory 2 4 shared))
      (memory 3 5 shared))
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

const ATOMIC_WAIT_NOTIFY: &str = r#"
    (module
      (memory $m 1 1 shared)
      (func (export "notify") (param i32 i32) (result i32)
        local.get 0 local.get 1 memory.atomic.notify offset=12 align=4)
      (func (export "wait32") (param i32 i32 i64) (result i32)
        local.get 0 local.get 1 local.get 2 memory.atomic.wait32 offset=20 align=4)
      (func (export "wait64") (param i32 i64 i64) (result i32)
        local.get 0 local.get 1 local.get 2 memory.atomic.wait64 offset=24 align=8))
"#;

const ATOMIC_NARROW_RMW_OPERATIONS: &str = r"
    (module
      (memory $m 1 1 shared)
      (func (param i32 i32 i64)
        local.get 0 local.get 1 i32.atomic.rmw8.add_u align=1 drop
        local.get 0 local.get 1 i32.atomic.rmw16.add_u align=2 drop
        local.get 0 local.get 2 i64.atomic.rmw8.add_u align=1 drop
        local.get 0 local.get 2 i64.atomic.rmw16.add_u align=2 drop
        local.get 0 local.get 2 i64.atomic.rmw32.add_u align=4 drop
        local.get 0 local.get 1 i32.atomic.rmw8.sub_u align=1 drop
        local.get 0 local.get 1 i32.atomic.rmw16.sub_u align=2 drop
        local.get 0 local.get 2 i64.atomic.rmw8.sub_u align=1 drop
        local.get 0 local.get 2 i64.atomic.rmw16.sub_u align=2 drop
        local.get 0 local.get 2 i64.atomic.rmw32.sub_u align=4 drop
        local.get 0 local.get 1 i32.atomic.rmw8.and_u align=1 drop
        local.get 0 local.get 1 i32.atomic.rmw16.and_u align=2 drop
        local.get 0 local.get 2 i64.atomic.rmw8.and_u align=1 drop
        local.get 0 local.get 2 i64.atomic.rmw16.and_u align=2 drop
        local.get 0 local.get 2 i64.atomic.rmw32.and_u align=4 drop
        local.get 0 local.get 1 i32.atomic.rmw8.or_u align=1 drop
        local.get 0 local.get 1 i32.atomic.rmw16.or_u align=2 drop
        local.get 0 local.get 2 i64.atomic.rmw8.or_u align=1 drop
        local.get 0 local.get 2 i64.atomic.rmw16.or_u align=2 drop
        local.get 0 local.get 2 i64.atomic.rmw32.or_u align=4 drop
        local.get 0 local.get 1 i32.atomic.rmw8.xor_u align=1 drop
        local.get 0 local.get 1 i32.atomic.rmw16.xor_u align=2 drop
        local.get 0 local.get 2 i64.atomic.rmw8.xor_u align=1 drop
        local.get 0 local.get 2 i64.atomic.rmw16.xor_u align=2 drop
        local.get 0 local.get 2 i64.atomic.rmw32.xor_u align=4 drop
        local.get 0 local.get 1 i32.atomic.rmw8.xchg_u align=1 drop
        local.get 0 local.get 1 i32.atomic.rmw16.xchg_u align=2 drop
        local.get 0 local.get 2 i64.atomic.rmw8.xchg_u align=1 drop
        local.get 0 local.get 2 i64.atomic.rmw16.xchg_u align=2 drop
        local.get 0 local.get 2 i64.atomic.rmw32.xchg_u align=4 drop
        local.get 0 local.get 1 local.get 1 i32.atomic.rmw8.cmpxchg_u align=1 drop
        local.get 0 local.get 1 local.get 1 i32.atomic.rmw16.cmpxchg_u align=2 drop
        local.get 0 local.get 2 local.get 2 i64.atomic.rmw8.cmpxchg_u align=1 drop
        local.get 0 local.get 2 local.get 2 i64.atomic.rmw16.cmpxchg_u align=2 drop
        local.get 0 local.get 2 local.get 2 i64.atomic.rmw32.cmpxchg_u align=4 drop))
";

fn compile_atomic_lifts(source: &str) -> (disrobe_core::scratch::ScratchDir, PathBuf) {
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
        .args(["--edition", "2024", "-O", "-C", "overflow-checks=off", "-o"])
        .arg(&executable_path)
        .arg(&source_path)
        .output()
        .expect("rustc must be available for the Rust lift gate");
    assert!(
        compile.status.success(),
        "rustc rejected atomic Rust lifts\n{}\n{source}",
        String::from_utf8_lossy(&compile.stderr)
    );
    (scratch, executable_path)
}

fn compile_and_run_atomic_lifts(source: &str) {
    let (_scratch, executable_path): (disrobe_core::scratch::ScratchDir, PathBuf) =
        compile_atomic_lifts(source);
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
fn indexes_imported_and_defined_shared_memories_in_memory_index_space() {
    let bytes: Vec<u8> = wat::parse_str(IMPORTED_SHARED_MEMORIES).expect("parse wat");
    let report: ThreadsReport = scan_threads(&bytes).expect("scan");
    let indices: Vec<u32> = report.shared_memories.keys().copied().collect();
    assert_eq!(indices, vec![1, 2]);

    let imported: &SharedMemoryRecord = report
        .shared_memories
        .get(&1)
        .expect("imported shared memory");
    assert_eq!(imported.memory_index, 1);
    assert_eq!(imported.initial, 2);
    assert_eq!(imported.maximum, Some(4));
    assert!(!imported.memory64);

    let defined: &SharedMemoryRecord = report
        .shared_memories
        .get(&2)
        .expect("defined shared memory");
    assert_eq!(defined.memory_index, 2);
    assert_eq!(defined.initial, 3);
    assert_eq!(defined.maximum, Some(5));
    assert!(!defined.memory64);
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

#[test]
fn wait_and_notify_rust_lifts_use_effective_addresses() {
    let bytes: Vec<u8> = wat::parse_str(ATOMIC_WAIT_NOTIFY).expect("parse wat");
    let report: ThreadsReport = scan_threads(&bytes).expect("scan");
    let notify: &AtomicOpRecord = report
        .atomic_ops
        .iter()
        .find(|op: &&AtomicOpRecord| op.mnemonic == "memory.atomic.notify")
        .expect("notify present");
    let wait32: &AtomicOpRecord = report
        .atomic_ops
        .iter()
        .find(|op: &&AtomicOpRecord| op.mnemonic == "memory.atomic.wait32")
        .expect("wait32 present");
    let wait64: &AtomicOpRecord = report
        .atomic_ops
        .iter()
        .find(|op: &&AtomicOpRecord| op.mnemonic == "memory.atomic.wait64")
        .expect("wait64 present");
    assert_eq!(notify.offset, 12);
    assert_eq!(wait32.offset, 20);
    assert_eq!(wait64.offset, 24);
    let source: String = format!(
        "fn wait_on_arc_mutex<M, E>(_: M, addr: u64, _: E, _: i64) -> u64 {{ addr }}\nfn notify_arc_mutex<M>(_: M, addr: u64, _: i32) -> u64 {{ addr }}\nfn main() {{\n{{ let memory: () = (); let addr: u64 = 5; let count: i32 = 1; let observed: u64 = {}; assert_eq!(observed, 17); }}\n{{ let memory: () = (); let addr: u64 = 5; let expected: i32 = 0; let timeout_ns: i64 = 0; let observed: u64 = {}; assert_eq!(observed, 25); }}\n{{ let memory: () = (); let addr: u64 = 5; let expected: i64 = 0; let timeout_ns: i64 = 0; let observed: u64 = {}; assert_eq!(observed, 29); }}\n}}\n",
        notify.rust_lift, wait32.rust_lift, wait64.rust_lift
    );
    compile_and_run_atomic_lifts(&source);
}

#[test]
fn wait_and_notify_effective_address_overflow_traps_in_optimized_lifts() {
    let bytes: Vec<u8> = wat::parse_str(ATOMIC_WAIT_NOTIFY).expect("parse wat");
    let report: ThreadsReport = scan_threads(&bytes).expect("scan");
    let notify: &AtomicOpRecord = report
        .atomic_ops
        .iter()
        .find(|op: &&AtomicOpRecord| op.mnemonic == "memory.atomic.notify")
        .expect("notify present");
    let wait32: &AtomicOpRecord = report
        .atomic_ops
        .iter()
        .find(|op: &&AtomicOpRecord| op.mnemonic == "memory.atomic.wait32")
        .expect("wait32 present");
    let wait64: &AtomicOpRecord = report
        .atomic_ops
        .iter()
        .find(|op: &&AtomicOpRecord| op.mnemonic == "memory.atomic.wait64")
        .expect("wait64 present");
    let source: String = format!(
        "fn wait_on_arc_mutex<M, E>(_: M, addr: u64, _: E, _: i64) -> u64 {{ addr }}\nfn notify_arc_mutex<M>(_: M, addr: u64, _: i32) -> u64 {{ addr }}\nfn main() {{\nlet Some(mode): Option<String> = std::env::args().nth(1) else {{ return; }};\nlet memory: () = (); let addr: u64 = u64::MAX;\nmatch mode.as_str() {{\n\"notify\" => {{ let count: i32 = 1; let _: u64 = {}; }},\n\"wait32\" => {{ let expected: i32 = 0; let timeout_ns: i64 = 0; let _: u64 = {}; }},\n\"wait64\" => {{ let expected: i64 = 0; let timeout_ns: i64 = 0; let _: u64 = {}; }},\n_ => panic!(\"unexpected mode\"),\n}}\n}}\n",
        notify.rust_lift, wait32.rust_lift, wait64.rust_lift
    );
    let (_scratch, executable_path): (disrobe_core::scratch::ScratchDir, PathBuf) =
        compile_atomic_lifts(&source);
    for mode in ["notify", "wait32", "wait64"] {
        let run: std::process::Output = Command::new(&executable_path)
            .arg(mode)
            .output()
            .expect("run optimized overflow lift");
        assert!(!run.status.success(), "{mode} overflow must trap");
        assert!(
            String::from_utf8_lossy(&run.stderr)
                .contains("DR-WASMDEOB-THREADS: atomic effective address overflow"),
            "{mode} must report the atomic effective-address trap"
        );
    }
}

#[test]
fn all_standard_narrow_atomic_rmw_and_cmpxchg_are_lifted() {
    let bytes: Vec<u8> = wat::parse_str(ATOMIC_NARROW_RMW_OPERATIONS).expect("parse wat");
    let report: ThreadsReport = scan_threads(&bytes).expect("scan");
    let observed: Vec<(&str, AtomicOpKind)> = report
        .atomic_ops
        .iter()
        .map(|op: &AtomicOpRecord| (op.mnemonic, op.kind))
        .collect();
    let expected: [(&str, AtomicOpKind); 35] = [
        ("i32.atomic.rmw8.add_u", AtomicOpKind::Rmw),
        ("i32.atomic.rmw16.add_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw8.add_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw16.add_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw32.add_u", AtomicOpKind::Rmw),
        ("i32.atomic.rmw8.sub_u", AtomicOpKind::Rmw),
        ("i32.atomic.rmw16.sub_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw8.sub_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw16.sub_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw32.sub_u", AtomicOpKind::Rmw),
        ("i32.atomic.rmw8.and_u", AtomicOpKind::Rmw),
        ("i32.atomic.rmw16.and_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw8.and_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw16.and_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw32.and_u", AtomicOpKind::Rmw),
        ("i32.atomic.rmw8.or_u", AtomicOpKind::Rmw),
        ("i32.atomic.rmw16.or_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw8.or_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw16.or_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw32.or_u", AtomicOpKind::Rmw),
        ("i32.atomic.rmw8.xor_u", AtomicOpKind::Rmw),
        ("i32.atomic.rmw16.xor_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw8.xor_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw16.xor_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw32.xor_u", AtomicOpKind::Rmw),
        ("i32.atomic.rmw8.xchg_u", AtomicOpKind::Rmw),
        ("i32.atomic.rmw16.xchg_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw8.xchg_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw16.xchg_u", AtomicOpKind::Rmw),
        ("i64.atomic.rmw32.xchg_u", AtomicOpKind::Rmw),
        ("i32.atomic.rmw8.cmpxchg_u", AtomicOpKind::Cmpxchg),
        ("i32.atomic.rmw16.cmpxchg_u", AtomicOpKind::Cmpxchg),
        ("i64.atomic.rmw8.cmpxchg_u", AtomicOpKind::Cmpxchg),
        ("i64.atomic.rmw16.cmpxchg_u", AtomicOpKind::Cmpxchg),
        ("i64.atomic.rmw32.cmpxchg_u", AtomicOpKind::Cmpxchg),
    ];
    assert_eq!(observed.as_slice(), expected.as_slice());
}

#[test]
fn narrow_atomic_rmw_and_cmpxchg_lifts_execute_with_wasm_widths() {
    let bytes: Vec<u8> = wat::parse_str(ATOMIC_NARROW_RMW_OPERATIONS).expect("parse wat");
    let report: ThreadsReport = scan_threads(&bytes).expect("scan");
    let rmw_cases: [(&str, &str, &str, &str, &str, &str, &str); 10] = [
        (
            "i32.atomic.rmw8.add_u",
            "AtomicU8",
            "i32",
            "250",
            "10",
            "250",
            "4",
        ),
        (
            "i32.atomic.rmw8.sub_u",
            "AtomicU8",
            "i32",
            "12",
            "5",
            "12",
            "7",
        ),
        (
            "i32.atomic.rmw8.and_u",
            "AtomicU8",
            "i32",
            "12",
            "10",
            "12",
            "8",
        ),
        (
            "i32.atomic.rmw8.or_u",
            "AtomicU8",
            "i32",
            "12",
            "10",
            "12",
            "14",
        ),
        (
            "i32.atomic.rmw8.xor_u",
            "AtomicU8",
            "i32",
            "12",
            "10",
            "12",
            "6",
        ),
        (
            "i32.atomic.rmw8.xchg_u",
            "AtomicU8",
            "i32",
            "12",
            "261",
            "12",
            "5",
        ),
        (
            "i32.atomic.rmw16.add_u",
            "AtomicU16",
            "i32",
            "65530",
            "10",
            "65530",
            "4",
        ),
        (
            "i64.atomic.rmw8.add_u",
            "AtomicU8",
            "i64",
            "250",
            "10",
            "250",
            "4",
        ),
        (
            "i64.atomic.rmw16.add_u",
            "AtomicU16",
            "i64",
            "65530",
            "10",
            "65530",
            "4",
        ),
        (
            "i64.atomic.rmw32.add_u",
            "AtomicU32",
            "i64",
            "4294967290",
            "10",
            "4294967290",
            "4",
        ),
    ];
    let mut source: String = String::from("fn main() {\n");
    for (mnemonic, cell_type, value_type, initial, value, observed, stored) in rmw_cases {
        let op: &AtomicOpRecord = report
            .atomic_ops
            .iter()
            .find(|op: &&AtomicOpRecord| op.mnemonic == mnemonic)
            .expect("narrow RMW present");
        writeln!(
            &mut source,
            "{{ let cell: std::sync::atomic::{cell_type} = std::sync::atomic::{cell_type}::new({initial}); let ptr: *const u8 = &cell as *const std::sync::atomic::{cell_type} as *const u8; let val: {value_type} = {value}; let before: {value_type} = {}; assert_eq!(before, {observed}); assert_eq!(cell.load(std::sync::atomic::Ordering::SeqCst), {stored}); }}",
            op.rust_lift
        )
        .expect("write narrow RMW source");
    }
    let cmpxchg_cases: [(&str, &str, &str, &str, &str); 5] = [
        ("i32.atomic.rmw8.cmpxchg_u", "AtomicU8", "i32", "268", "261"),
        (
            "i32.atomic.rmw16.cmpxchg_u",
            "AtomicU16",
            "i32",
            "65548",
            "65541",
        ),
        ("i64.atomic.rmw8.cmpxchg_u", "AtomicU8", "i64", "268", "261"),
        (
            "i64.atomic.rmw16.cmpxchg_u",
            "AtomicU16",
            "i64",
            "65548",
            "65541",
        ),
        (
            "i64.atomic.rmw32.cmpxchg_u",
            "AtomicU32",
            "i64",
            "4294967308",
            "4294967301",
        ),
    ];
    for (mnemonic, cell_type, value_type, old, new) in cmpxchg_cases {
        let op: &AtomicOpRecord = report
            .atomic_ops
            .iter()
            .find(|op: &&AtomicOpRecord| op.mnemonic == mnemonic)
            .expect("narrow cmpxchg present");
        writeln!(
            &mut source,
            "{{ let cell: std::sync::atomic::{cell_type} = std::sync::atomic::{cell_type}::new(12); let ptr: *const u8 = &cell as *const std::sync::atomic::{cell_type} as *const u8; let old: {value_type} = {old}; let new: {value_type} = {new}; let before: {value_type} = {}; assert_eq!(before, 12); assert_eq!(cell.load(std::sync::atomic::Ordering::SeqCst), 5); }}",
            op.rust_lift
        )
        .expect("write narrow cmpxchg source");
    }
    source.push_str("}\n");
    compile_and_run_atomic_lifts(&source);
}
