#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{EvalIndirectionResult, peel_eval_indirection};

const CONST: &str = include_str!("../corpus/esoteric/eval-indirection-const.js");
const NEWFN: &str = include_str!("../corpus/esoteric/eval-indirection-newfn.js");

#[test]
fn folds_constant_eval_argument() {
    let res: EvalIndirectionResult = peel_eval_indirection(CONST);
    assert!(res.stats.constant_folded >= 1);
    assert!(res.rewritten.contains("var __recovered = 42;"));
    assert!(res.rewritten.contains("dr-eval-folded"));
}

#[test]
fn folds_new_function_iife() {
    let res: EvalIndirectionResult = peel_eval_indirection(NEWFN);
    assert!(res.stats.constant_folded >= 1);
    assert!(res.rewritten.contains("return 7 * 6;"));
}

#[test]
fn ast_walk_records_eval_callsites() {
    let res: EvalIndirectionResult = peel_eval_indirection(CONST);
    assert!(res.stats.eval_calls_seen >= 1);
}

#[test]
fn ast_walk_records_function_constructor_callsites() {
    let res: EvalIndirectionResult = peel_eval_indirection(NEWFN);
    assert!(res.stats.function_calls_seen >= 1);
}

#[test]
fn non_constant_eval_emits_detect_only_marker() {
    let src: &str = "var dyn = compute(); eval(dyn);";
    let res: EvalIndirectionResult = peel_eval_indirection(src);
    assert_eq!(res.stats.constant_folded, 0);
    assert!(res.stats.detect_only_markers >= 1);
}
