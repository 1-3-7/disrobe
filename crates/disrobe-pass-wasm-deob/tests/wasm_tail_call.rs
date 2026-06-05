#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_wasm_deob::{TailCallKind, TailCallRecord, TailCallReport, scan_tail_calls};

const TAIL_WAT: &str = r#"
    (module
      (func $callee (param i32) (result i32) local.get 0)
      (func (export "tail") (param i32) (result i32)
        local.get 0
        return_call $callee))
"#;

#[test]
fn return_call_lifts_with_inline_always_attribute() {
    let bytes: Vec<u8> = wat::parse_str(TAIL_WAT).expect("parse wat");
    let report: TailCallReport = scan_tail_calls(&bytes).expect("scan");
    assert_eq!(report.direct_count(), 1);
    let rec: &TailCallRecord = report
        .records
        .iter()
        .find(|r: &&TailCallRecord| matches!(r.kind, TailCallKind::Direct))
        .expect("direct tail");
    assert!(rec.rust_form.contains("#[inline(always)]"));
    assert!(rec.rust_form.contains("return fn_"));
}
