#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::BTreeSet;

use disrobe_pass_js_deob::{
    JscramblerOptions, JscramblerOutput, JscramblerTransform, JscramblerTransformStats,
    deobfuscate_jscrambler,
};

fn opts_with(t: JscramblerTransform) -> JscramblerOptions {
    let mut set: BTreeSet<JscramblerTransform> = BTreeSet::new();
    set.insert(t);
    JscramblerOptions {
        i_have_authorization: false,
        transforms: set,
    }
}

fn is_recorded(out: &JscramblerOutput, t: JscramblerTransform) -> bool {
    out.per_transform
        .iter()
        .any(|(k, _): &(JscramblerTransform, JscramblerTransformStats)| *k == t)
}

fn stats_for(out: &JscramblerOutput, t: JscramblerTransform) -> &JscramblerTransformStats {
    out.per_transform
        .iter()
        .find(|(k, _): &&(JscramblerTransform, JscramblerTransformStats)| *k == t)
        .map(|(_, s): &(JscramblerTransform, JscramblerTransformStats)| s)
        .expect("transform recorded")
}

#[test]
fn assertions_removal_is_detect_only_and_does_not_mutate_source() {
    let src: &str = "function f(){ /*assert-strip*/ return 1; }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::AssertionsRemoval);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
    let s: &JscramblerTransformStats = stats_for(&out, JscramblerTransform::AssertionsRemoval);
    assert!(s.matched >= 1, "expected detection marker");
    assert_eq!(s.reversed, 0, "detect-only must not reverse");
}

#[test]
fn assertions_removal_detect_returns_zero_on_unmarked_source() {
    let src: &str = "function f(){ return 1; }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::AssertionsRemoval);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
    assert!(
        !is_recorded(&out, JscramblerTransform::AssertionsRemoval),
        "an undetected transform must not run: {:?}",
        out.per_transform
    );
}

#[test]
fn constant_folding_undoes_addition() {
    let src: &str = "var x = 2 + 3;";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::ConstantFolding);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(out.source.contains('5'));
    let s: &JscramblerTransformStats = stats_for(&out, JscramblerTransform::ConstantFolding);
    assert!(s.reversed >= 1);
}

#[test]
fn constant_folding_undoes_multiplication_and_subtraction() {
    let src: &str = "var a = 6 * 7; var b = 10 - 3;";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::ConstantFolding);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(out.source.contains("42"));
    assert!(out.source.contains('7'));
}

#[test]
fn constant_folding_leaves_division_by_zero_alone() {
    let src: &str = "var x = 5 / 0;";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::ConstantFolding);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(out.source.contains("5 / 0"));
}

#[test]
fn constant_folding_skips_non_literal_operands() {
    let src: &str = "var x = a + b;";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::ConstantFolding);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
}

#[test]
fn dead_code_elimination_is_detect_only() {
    let src: &str = "function f(){ /*dce-strip*/ return 1; }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::DeadCodeElimination);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
    let s: &JscramblerTransformStats = stats_for(&out, JscramblerTransform::DeadCodeElimination);
    assert!(s.matched >= 1);
    assert_eq!(s.reversed, 0);
}

#[test]
fn dead_code_elimination_detect_zero_on_clean_source() {
    let src: &str = "var a = 1; if (a) { run(); }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::DeadCodeElimination);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
    assert!(
        !is_recorded(&out, JscramblerTransform::DeadCodeElimination),
        "an undetected transform must not run: {:?}",
        out.per_transform
    );
}

#[test]
fn debug_code_elimination_is_detect_only() {
    let src: &str = "function f(){ /*debug-strip*/ console.log('x'); }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::DebugCodeElimination);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
    let s: &JscramblerTransformStats = stats_for(&out, JscramblerTransform::DebugCodeElimination);
    assert!(s.matched >= 1);
    assert_eq!(s.reversed, 0);
}

#[test]
fn duplicate_literals_local_only_reuses_obfuscation_reverser() {
    let src: &str = "var T = ['alpha', 'beta', 'gamma']; console.log(T[0]); console.log(T[2]);";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::DuplicateLiteralsRemoval);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(out.source.contains("\"alpha\""));
    assert!(out.source.contains("\"gamma\""));
    let s: &JscramblerTransformStats =
        stats_for(&out, JscramblerTransform::DuplicateLiteralsRemoval);
    assert_eq!(s.reversed, 2);
}

#[test]
fn duplicate_literals_local_only_no_op_without_table() {
    let src: &str = "var x = 1; console.log(x);";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::DuplicateLiteralsRemoval);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
}

#[test]
fn identifiers_renaming_optimization_maps_hex_idents_to_stable_v_n() {
    let src: &str = "var a0_0xabcd = 1; var a0_0xabcd = 2; var a1_0xbeef = 3;";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::IdentifiersRenaming);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(out.source.contains("v_1"));
    assert!(out.source.contains("v_2"));
    let v1_occurrences: usize = out.source.matches("v_1").count();
    assert!(
        v1_occurrences >= 2,
        "rename must be stable across occurrences"
    );
}

#[test]
fn identifiers_renaming_no_op_on_already_readable_idents() {
    let src: &str = "var foo = 1; var bar = 2;";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::IdentifiersRenaming);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
}

#[test]
fn whitespace_removal_beautifies_dense_single_line_blob() {
    let dense: String = "function f(){var a=1;var b=2;return a+b;}".repeat(20);
    let opts: JscramblerOptions = opts_with(JscramblerTransform::WhitespaceRemoval);
    let out: JscramblerOutput = deobfuscate_jscrambler(&dense, &opts).expect("ok");
    let newlines: usize = out.source.matches('\n').count();
    assert!(
        newlines > 5,
        "beautified output should contain multiple newlines, got {newlines}"
    );
    let s: &JscramblerTransformStats = stats_for(&out, JscramblerTransform::WhitespaceRemoval);
    assert!(s.matched >= 1);
}

#[test]
fn whitespace_removal_is_noop_on_already_formatted_source() {
    let src: &str = "function f() {\n  var a = 1;\n  return a;\n}\n";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::WhitespaceRemoval);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
}

#[test]
fn optimization_chain_runs_each_detected_step_once_in_order() {
    let src: &str = "var x = 2 + 3; var T = ['a','b']; T[0];";
    let mut set: BTreeSet<JscramblerTransform> = BTreeSet::new();
    for t in [
        JscramblerTransform::AssertionsRemoval,
        JscramblerTransform::ConstantFolding,
        JscramblerTransform::DeadCodeElimination,
        JscramblerTransform::DebugCodeElimination,
        JscramblerTransform::DuplicateLiteralsRemoval,
        JscramblerTransform::IdentifiersRenaming,
        JscramblerTransform::WhitespaceRemoval,
    ] {
        set.insert(t);
    }
    let opts: JscramblerOptions = JscramblerOptions {
        i_have_authorization: false,
        transforms: set.clone(),
    };
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    let expected: Vec<JscramblerTransform> = set
        .intersection(&out.detection.detected_transforms)
        .copied()
        .collect();
    let ran: Vec<JscramblerTransform> = out
        .per_transform
        .iter()
        .map(|(k, _): &(JscramblerTransform, JscramblerTransformStats)| *k)
        .collect();
    assert_eq!(
        ran, expected,
        "each requested and detected step runs once, in order"
    );
    assert!(
        ran.contains(&JscramblerTransform::ConstantFolding),
        "the folded addition must be detected and reversed: {ran:?}"
    );
    assert!(out.source.contains('5'));
    assert!(out.source.contains("\"a\""));
}
