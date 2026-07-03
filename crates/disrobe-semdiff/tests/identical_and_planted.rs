#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_nir::NirModule;
use disrobe_nir_lift::lift_wasm_module;
use disrobe_semdiff::{SemanticDiff, diff};

const BASE_WAT: &str = r#"
(module
  (import "env" "log" (func $log (param i32)))
  (func $checksum (export "checksum") (param i32) (result i32)
    (i32.xor (local.get 0) (i32.const 305419896)))
  (func $emit (export "emit") (param i32)
    (call $log (call $checksum (local.get 0)))))
"#;

const SAME_SOURCE_DIFFERENT_LAYOUT_WAT: &str = r#"
(module
  (import "env" "log" (func $log (param i32)))
  (memory (export "memory") 1)
  (func $checksum (export "checksum") (param i32) (result i32)
    (i32.xor (local.get 0) (i32.const 305419896)))
  (func $emit (export "emit") (param i32)
    (call $log (call $checksum (local.get 0)))))
"#;

const CHECKSUM_KEY_CHANGED_WAT: &str = r#"
(module
  (import "env" "log" (func $log (param i32)))
  (func $checksum (export "checksum") (param i32) (result i32)
    (i32.xor (local.get 0) (i32.const 2596069104)))
  (func $emit (export "emit") (param i32)
    (call $log (call $checksum (local.get 0)))))
"#;

const CHECKSUM_OP_CHANGED_WAT: &str = r#"
(module
  (import "env" "log" (func $log (param i32)))
  (func $checksum (export "checksum") (param i32) (result i32)
    (i32.add (local.get 0) (i32.const 305419896)))
  (func $emit (export "emit") (param i32)
    (call $log (call $checksum (local.get 0)))))
"#;

fn lift(wat: &str) -> NirModule {
    let bytes: Vec<u8> = wat::parse_str(wat).expect("assemble wat");
    lift_wasm_module(&bytes).expect("lift wasm module")
}

#[test]
fn the_same_artifact_diffs_to_nothing() {
    let module: NirModule = lift(BASE_WAT);
    let report: SemanticDiff = diff(&module, &module);
    assert!(
        report.is_empty(),
        "an artifact is identical to itself: {report:?}"
    );
}

#[test]
fn two_builds_of_the_same_logic_diff_to_nothing_despite_layout_change() {
    let base: NirModule = lift(BASE_WAT);
    let other: NirModule = lift(SAME_SOURCE_DIFFERENT_LAYOUT_WAT);
    let report: SemanticDiff = diff(&base, &other);
    assert!(
        report.is_empty(),
        "adding a memory section relocates nothing in the function bodies: {report:?}"
    );
}

#[test]
fn a_changed_constant_flags_exactly_that_one_function() {
    let base: NirModule = lift(BASE_WAT);
    let other: NirModule = lift(CHECKSUM_KEY_CHANGED_WAT);
    let report: SemanticDiff = diff(&base, &other);
    assert!(
        report.is_changed("checksum"),
        "the xor key changed: {report:?}"
    );
    assert!(
        !report.affects("emit"),
        "emit is byte-identical: {report:?}"
    );
    let changed: Vec<&str> = report.changed().collect();
    assert_eq!(changed, vec!["checksum"], "exactly one function flagged");
}

#[test]
fn a_changed_operator_flags_exactly_that_one_function() {
    let base: NirModule = lift(BASE_WAT);
    let other: NirModule = lift(CHECKSUM_OP_CHANGED_WAT);
    let report: SemanticDiff = diff(&base, &other);
    assert!(report.is_changed("checksum"), "xor became add: {report:?}");
    assert!(!report.affects("emit"));
    assert_eq!(report.count(), 1);
}

#[test]
fn the_diff_is_symmetric_in_what_it_flags() {
    let base: NirModule = lift(BASE_WAT);
    let other: NirModule = lift(CHECKSUM_KEY_CHANGED_WAT);
    let forward_diff: SemanticDiff = diff(&base, &other);
    let backward_diff: SemanticDiff = diff(&other, &base);
    let forward: Vec<String> = forward_diff.changed().map(str::to_owned).collect();
    let backward: Vec<String> = backward_diff.changed().map(str::to_owned).collect();
    assert_eq!(forward, backward);
}
