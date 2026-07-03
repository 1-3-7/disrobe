#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{ClosureAdvancedReport, undo_closure_advanced};

#[test]
fn detects_advanced_mangled_props() {
    let src: &str = "var x={};x.a_=1;x.b_=2;x.c_=3;x.d_=4;return x;";
    let r: ClosureAdvancedReport = undo_closure_advanced(src);
    assert!(r.detected, "should detect ADVANCED pattern, got {r:?}");
    assert_eq!(
        r.property_renames.get("a").map(String::as_str),
        Some("args"),
        "the mangled property `a` must restore to `args`; got {:?}",
        r.property_renames,
    );
}

#[test]
fn restore_plan_uses_member_hints() {
    let src: &str = "fn.t(promise.then(()=>1));fn.t(promise2.then(()=>2));fn.t(promise3.then(()=>3));fn.t(promise4.then(()=>4));";
    let r: ClosureAdvancedReport = undo_closure_advanced(src);
    assert!(r.detected);
    assert_eq!(
        r.property_renames.get("t").map(String::as_str),
        Some("target"),
        "the mangled property `t`, hinted by the `.then` member access, must restore to `target`; got {:?}",
        r.property_renames,
    );
}

#[test]
fn strips_goog_debug_calls() {
    let src: &str = "var x={};x.a_=1;x.b_=2;x.c_=3;x.d_=4;goog.DEBUG && console.log('dev');";
    let r: ClosureAdvancedReport = undo_closure_advanced(src);
    assert!(r.dead_code_stripped_bytes > 0);
    assert!(!r.rewritten.contains("goog.DEBUG"));
}
