#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_wasm_deob::{SimdOpRecord, SimdReport, scan_simd};

const SIMD_WAT: &str = r#"
    (module
      (memory 1)
      (func (export "splat_add") (result v128)
        i32.const 1 i32x4.splat
        i32.const 2 i32x4.splat
        i32x4.add))
"#;

#[test]
fn detects_simd_ops_and_lifts_to_wasm32_intrinsics() {
    let bytes: Vec<u8> = wat::parse_str(SIMD_WAT).expect("parse wat");
    let report: SimdReport = scan_simd(&bytes).expect("scan");
    assert!(report.uses_v128);
    assert!(report.op_count() >= 2);
    let add: &SimdOpRecord = report
        .ops
        .iter()
        .find(|o: &&SimdOpRecord| o.mnemonic == "i32x4.add")
        .expect("add present");
    assert!(add.rust_lift.contains("i32x4_add"));
}
