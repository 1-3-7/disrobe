#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_wasm_deob::{AtomicOpKind, AtomicOpRecord, ThreadsReport, scan_threads};

const ATOMIC_RMW: &str = r#"
    (module
      (memory $m 1 1 shared)
      (func (export "inc") (param i32) (result i32)
        local.get 0
        i32.const 1
        i32.atomic.rmw.add offset=0 align=4))
"#;

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
