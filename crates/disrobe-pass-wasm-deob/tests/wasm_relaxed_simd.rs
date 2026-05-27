#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_wasm_deob::{SimdOpRecord, SimdReport, scan_simd};

const RELAXED_WAT: &str = r#"
    (module
      (memory 1)
      (func (export "madd") (param v128 v128 v128) (result v128)
        local.get 0 local.get 1 local.get 2
        f32x4.relaxed_madd))
"#;

#[test]
fn relaxed_simd_marks_conservatively_in_lift() {
    let bytes: Vec<u8> = wat::parse_str(RELAXED_WAT).expect("parse wat");
    let report: SimdReport = scan_simd(&bytes).expect("scan");
    assert!(report.uses_relaxed);
    assert_eq!(report.relaxed_count(), 1);
    let madd: &SimdOpRecord = report
        .ops
        .iter()
        .find(|o: &&SimdOpRecord| o.mnemonic == "f32x4.relaxed_madd")
        .expect("madd present");
    assert!(madd.rust_lift.contains("conservative lift"));
    assert!(madd.rust_lift.contains("relaxed_madd"));
}
