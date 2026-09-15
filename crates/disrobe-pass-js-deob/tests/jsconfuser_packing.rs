#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{PackingReversalResult, reverse_packing};

#[test]
fn unwraps_minimal_dean_edwards_payload() {
    let src: &str = "var keep = 1; eval(function(p,a,c,k,e,d){return p}('alert(1)',62,1,'alert'.split('|'),0,{})); var more = 2;";
    let r: PackingReversalResult = reverse_packing(src);
    assert_eq!(r.blocks_expanded, 1);
    let out: &String = &r.rewritten_source;
    assert!(out.contains("alert(1)"), "alert leak: {out}");
    assert!(
        !out.contains("eval(function"),
        "wrapper still present: {out}"
    );
    assert!(out.contains("var keep"));
    assert!(out.contains("var more"));
}

#[test]
fn substitutes_indices_via_radix_dictionary() {
    let src: &str = "eval(function(p,a,c,k,e,d){return p}('1 0',10,2,'hi|bye'.split('|'),0,{}));";
    let r: PackingReversalResult = reverse_packing(src);
    assert_eq!(r.blocks_expanded, 1);
    assert!(r.rewritten_source.contains("bye hi"));
}

#[test]
fn unwraps_payload_with_punctuation_preserved() {
    let src: &str = "eval(function(p,a,c,k,e,r){return p}('var 0 = 1;',10,1,'x'.split('|'),0,{}));";
    let r: PackingReversalResult = reverse_packing(src);
    assert_eq!(r.blocks_expanded, 1);
    assert!(r.rewritten_source.contains("var x = 1;"));
}

#[test]
fn unwraps_two_packed_payloads_in_one_source() {
    let src: &str = "eval(function(p,a,c,k,e,d){return p}('0',10,1,'first'.split('|'),0,{}));\neval(function(p,a,c,k,e,d){return p}('0',10,1,'second'.split('|'),0,{}));";
    let r: PackingReversalResult = reverse_packing(src);
    assert_eq!(r.blocks_expanded, 2);
    assert!(r.rewritten_source.contains("first"));
    assert!(r.rewritten_source.contains("second"));
}

#[test]
fn leaves_unrelated_eval_alone() {
    let src: &str = "eval('var x = 1;');";
    let r: PackingReversalResult = reverse_packing(src);
    assert_eq!(r.blocks_expanded, 0);
    assert_eq!(r.rewritten_source, src);
}
