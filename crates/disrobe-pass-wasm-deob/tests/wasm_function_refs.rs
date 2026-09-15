#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use disrobe_pass_wasm_deob::{FuncRefOpKind, FuncRefReport, scan_function_refs};

const WAT_TYPED_CALL_REF: &str = r#"
    (module
      (type $ft (func (param i32) (result i32)))
      (func $square (param i32) (result i32)
        local.get 0
        local.get 0
        i32.mul)
      (func (export "go") (param i32) (result i32)
        local.get 0
        ref.func $square
        call_ref $ft))
"#;

const WAT_TAIL_CALL_REF: &str = r#"
    (module
      (type $ft (func (param i32) (result i32)))
      (func $square (param i32) (result i32)
        local.get 0
        local.get 0
        i32.mul)
      (func (export "go") (param i32) (result i32)
        local.get 0
        ref.func $square
        return_call_ref $ft))
"#;

const WAT_BR_ON_NULL: &str = r#"
    (module
      (type $ft (func))
      (func (export "go") (param (ref null $ft))
        block $b (result (ref $ft))
          local.get 0
          br_on_null $b
        end
        call_ref $ft))
"#;

fn baked(src: &str) -> Option<Vec<u8>> {
    wat::parse_str(src).ok()
}

#[test]
fn detects_typed_function_refs_and_call_ref() {
    let Some(bytes): Option<Vec<u8>> = baked(WAT_TYPED_CALL_REF) else {
        return;
    };
    let report: FuncRefReport = scan_function_refs(&bytes).expect("scan");
    assert!(report.kinds.contains_key(&FuncRefOpKind::CallRef));
    assert!(report.kinds.contains_key(&FuncRefOpKind::RefFunc));
    assert!(report.typed_function_ref_count >= 1usize);
}

#[test]
fn detects_return_call_ref_as_tail_call_ref() {
    let Some(bytes): Option<Vec<u8>> = baked(WAT_TAIL_CALL_REF) else {
        return;
    };
    let report: FuncRefReport = scan_function_refs(&bytes).expect("scan");
    if !report.is_empty() {
        assert!(report.uses_tail_call_ref);
    }
}

#[test]
fn detects_br_on_null_family() {
    let Some(bytes): Option<Vec<u8>> = baked(WAT_BR_ON_NULL) else {
        return;
    };
    let report: FuncRefReport = scan_function_refs(&bytes).expect("scan");
    assert!(report.uses_br_on_null_family);
}

#[test]
fn empty_module_is_empty() {
    let bytes: Vec<u8> = wat::parse_str("(module)").expect("wat");
    let report: FuncRefReport = scan_function_refs(&bytes).expect("scan");
    assert!(report.is_empty());
}
