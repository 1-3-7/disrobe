#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use disrobe_pass_wasm_deob::{GcExternReport, scan_gc_extern};

const WAT: &str = r#"
    (module
      (func (export "round_trip") (param externref) (result externref)
        local.get 0
        any.convert_extern
        extern.convert_any))
"#;

fn baked(src: &str) -> Option<Vec<u8>> {
    wat::parse_str(src).ok()
}

#[test]
fn detects_extern_internalize_and_externalize_pair() {
    let Some(bytes): Option<Vec<u8>> = baked(WAT) else {
        return;
    };
    let report: GcExternReport = scan_gc_extern(&bytes).expect("scan");
    assert_eq!(report.any_to_extern, 1usize);
    assert_eq!(report.extern_to_any, 1usize);
    assert!(!report.is_empty());
}

#[test]
fn empty_module_is_empty() {
    let bytes: Vec<u8> = wat::parse_str("(module)").expect("wat");
    let report: GcExternReport = scan_gc_extern(&bytes).expect("scan");
    assert!(report.is_empty());
}
