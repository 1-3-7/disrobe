#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_wasm_deob::{
    EhConstruct, EhFunctionSummary, EhModuleSummary, EhTagSummary, lift_tag_to_rust_result,
    scan_module_eh,
};

fn assemble(wat_text: &str) -> Vec<u8> {
    wat::parse_str(wat_text).expect("the test fixture wat must assemble cleanly")
}

const LEGACY_TRY_THROW: &str = r#"
(module
  (tag $oops (param i32))
  (func (export "may_throw")
    try
      i32.const 7
      throw $oops
    catch $oops
      drop
    end))
"#;

const MODERN_TRY_TABLE: &str = r#"
(module
  (tag $oops (param i32))
  (func (export "may_throw") (result i32)
    block $on_throw (result i32)
      try_table (catch $oops $on_throw)
        i32.const 42
        throw $oops
      end
      i32.const 0
    end))
"#;

const THROW_REF_AND_CATCH_ALL: &str = r#"
(module
  (tag $oops (param i32))
  (func (export "h")
    block $exn (result exnref)
      try_table (catch_all_ref $exn)
        i32.const 1
        throw $oops
      end
      return
    end
    throw_ref))
"#;

const RETHROW_DELEGATE: &str = r#"
(module
  (tag $oops (param i32))
  (func (export "f")
    try
      try
        i32.const 1
        throw $oops
      delegate 0
    catch_all
      rethrow 0
    end))
"#;

#[test]
fn legacy_try_throw_records_throw_and_catch_for_tag_zero() {
    let bytes: Vec<u8> = assemble(LEGACY_TRY_THROW);
    let summary: EhModuleSummary = scan_module_eh(&bytes).expect("scan must succeed");
    assert_eq!(summary.tag_section_count, 1);
    assert!(summary.uses_exception_handling());
    assert!(summary.uses_legacy_eh());
    let func: &EhFunctionSummary = summary
        .functions
        .get(&0)
        .expect("must record the single function");
    assert_eq!(
        func.legacy_try_blocks, 1,
        "must count one legacy `try` block"
    );
    assert!(
        func.constructs.contains(&EhConstruct::Throw),
        "must record the Throw construct"
    );
    assert!(
        func.constructs.contains(&EhConstruct::Catch),
        "must record the Catch construct"
    );
    let tag0: &EhTagSummary = func
        .per_tag
        .get(&0)
        .expect("per-tag stats for tag 0 must be present");
    assert!(
        tag0.throws >= 1,
        "tag 0 must have >=1 throw, got {}",
        tag0.throws
    );
    assert!(
        tag0.catches >= 1,
        "tag 0 must have >=1 catch, got {}",
        tag0.catches
    );
}

#[test]
fn modern_try_table_records_try_table_and_per_tag_catch() {
    let bytes: Vec<u8> = assemble(MODERN_TRY_TABLE);
    let summary: EhModuleSummary = scan_module_eh(&bytes).expect("scan must succeed");
    assert!(
        summary.uses_modern_eh(),
        "try_table must flip the modern-EH bit"
    );
    let func: &EhFunctionSummary = summary
        .functions
        .get(&0)
        .expect("must record the single function");
    assert_eq!(func.try_table_blocks, 1, "must see exactly one try_table");
    assert!(
        func.constructs.contains(&EhConstruct::TryTable),
        "must record the TryTable construct"
    );
    let tag0: &EhTagSummary = func
        .per_tag
        .get(&0)
        .expect("the inline `catch $oops` must populate tag 0");
    assert!(tag0.throws >= 1);
    assert!(tag0.catches >= 1);
}

#[test]
fn throw_ref_and_catch_all_ref_are_classified_as_modern_constructs() {
    let bytes: Vec<u8> = assemble(THROW_REF_AND_CATCH_ALL);
    let summary: EhModuleSummary = scan_module_eh(&bytes).expect("scan must succeed");
    let func: &EhFunctionSummary = summary.functions.get(&0).expect("must record the function");
    assert!(
        func.throw_refs >= 1,
        "throw_ref must increment throw_refs counter"
    );
    assert!(
        func.constructs.contains(&EhConstruct::ThrowRef),
        "must record ThrowRef construct"
    );
    assert!(
        func.catch_all_ref_arms >= 1,
        "catch_all_ref arm must be counted"
    );
}

#[test]
fn rethrow_and_delegate_in_legacy_eh_module_are_recorded() {
    let bytes: Vec<u8> = assemble(RETHROW_DELEGATE);
    let summary: EhModuleSummary = scan_module_eh(&bytes).expect("scan must succeed");
    let func: &EhFunctionSummary = summary.functions.get(&0).expect("must record the function");
    assert!(func.rethrows >= 1, "must count the rethrow");
    assert!(func.delegates >= 1, "must count the delegate");
    assert!(
        func.constructs.contains(&EhConstruct::Rethrow),
        "must record Rethrow"
    );
    assert!(
        func.constructs.contains(&EhConstruct::Delegate),
        "must record Delegate"
    );
    assert!(summary.uses_legacy_eh());
}

#[test]
fn lift_tag_to_rust_result_round_trips_through_summary() {
    let bytes: Vec<u8> = assemble(LEGACY_TRY_THROW);
    let summary: EhModuleSummary = scan_module_eh(&bytes).expect("scan must succeed");
    assert!(!summary.per_tag.is_empty());
    let (tag, _): (&u32, &EhTagSummary) = summary
        .per_tag
        .iter()
        .next()
        .expect("at least one per-tag entry");
    let rust: String = lift_tag_to_rust_result(*tag, "may_throw");
    let expected_ty: String = format!("Exception{tag}");
    assert!(
        rust.contains(&expected_ty),
        "expected `{expected_ty}` in rust output:\n{rust}"
    );
    assert!(rust.contains("Result<()"));
    assert!(rust.contains("may_throw"));
}
