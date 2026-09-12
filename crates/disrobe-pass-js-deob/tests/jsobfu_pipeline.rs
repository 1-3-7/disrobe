#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{
    JsObfuDetection, JsObfuRewriteStats, detect_jsobfu, rewrite_bracket_access,
};

const SAMPLE: &str = include_str!("../../../corpus/src/javascript/jsobfu-sample.js");

#[test]
fn jsobfu_sample_detects_as_matched() {
    let det: JsObfuDetection = detect_jsobfu(SAMPLE);
    assert!(det.matched, "expected JSObfu match: {det:?}");
    assert!(det.bracket_string_access_count >= 3);
    assert!(det.array_join_count >= 1);
    assert!(det.eval_call_count >= 1);
}

#[test]
fn jsobfu_sample_rewrites_to_readable_form() {
    let (out, stats): (String, JsObfuRewriteStats) = rewrite_bracket_access(SAMPLE);
    assert!(out.contains("'hello world'"));
    assert!(out.contains("console.log"));
    assert!(out.contains("Math.floor"));
    assert!(out.contains("JSON.stringify"));
    assert!(out.contains("document.title"));
    assert!(stats.bracket_to_dot_rewrites >= 4);
    assert_eq!(stats.array_join_folded, 1);
}

#[test]
fn jsobfu_pipeline_leaves_non_global_brackets_alone() {
    let (out, _stats): (String, JsObfuRewriteStats) = rewrite_bracket_access(SAMPLE);
    assert!(
        out.contains("window.eval"),
        "window should be a recognized LHS: {out}"
    );
}
