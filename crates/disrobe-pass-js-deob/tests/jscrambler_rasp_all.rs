#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::BTreeSet;

use disrobe_pass_js_deob::{
    JscramblerOptions, JscramblerOutput, JscramblerTransform, JscramblerTransformStats,
    deobfuscate_jscrambler,
};

fn opts_with(t: JscramblerTransform, auth: bool) -> JscramblerOptions {
    let mut set: BTreeSet<JscramblerTransform> = BTreeSet::new();
    set.insert(t);
    JscramblerOptions {
        i_have_authorization: auth,
        transforms: set,
    }
}

fn stats_for(out: &JscramblerOutput, t: JscramblerTransform) -> &JscramblerTransformStats {
    out.per_transform
        .iter()
        .find(|(k, _): &&(JscramblerTransform, JscramblerTransformStats)| *k == t)
        .map(|(_, s): &(JscramblerTransform, JscramblerTransformStats)| s)
        .expect("transform recorded")
}

#[test]
fn anti_debugging_strips_debugger_when_authorized() {
    let src: &str = "function f(){ debugger; return 1; }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::AntiDebugging, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(!out.source.contains("debugger"));
    assert!(out.source.contains("return 1"));
}

#[test]
fn anti_debugging_strips_set_interval_debugger_loop() {
    let src: &str = "setInterval(function(){ debugger; check(); }, 100);";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::AntiDebugging, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(!out.source.contains("debugger"));
}

#[test]
fn anti_debugging_strips_iife_debugger_wrapper() {
    let src: &str = "(function(){ debugger; }());";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::AntiDebugging, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(!out.source.contains("debugger"));
}

#[test]
fn anti_debugging_strips_console_debug_trap() {
    let src: &str = "console['debug']();";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::AntiDebugging, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(!out.source.contains("console['debug']"));
}

#[test]
fn anti_debugging_detect_only_without_authorization() {
    let src: &str = "function f(){ debugger; }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::AntiDebugging, false);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
    let s: &JscramblerTransformStats = stats_for(&out, JscramblerTransform::AntiDebugging);
    assert!(s.matched >= 1);
    assert!(s.skipped >= 1);
}

#[test]
fn anti_monkey_patching_strips_object_freeze_prototype() {
    let src: &str = "Object.freeze(Array.prototype); var x = 1;";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::AntiMonkeyPatching, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(!out.source.contains("Object.freeze"));
    assert!(out.source.contains("var x = 1"));
}

#[test]
fn anti_monkey_patching_strips_define_property_on_object_prototype() {
    let src: &str = "Object.defineProperty(Object.prototype, 'x', { value: 1, writable: false });";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::AntiMonkeyPatching, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(!out.source.contains("Object.defineProperty"));
}

#[test]
fn anti_monkey_patching_detect_only_without_authorization() {
    let src: &str = "Object.freeze(Array.prototype);";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::AntiMonkeyPatching, false);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
    let s: &JscramblerTransformStats = stats_for(&out, JscramblerTransform::AntiMonkeyPatching);
    assert!(s.matched >= 1);
    assert!(s.skipped >= 1);
}

#[test]
fn anti_tampering_pins_the_tostring_probe_to_the_length_it_is_checked_against() {
    let src: &str = "var n = fn.toString().replace(/ /g,'').length; if (n !== 100) tamper();";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::AntiTampering, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, "var n = 100; if (n !== 100) tamper();");
}

#[test]
fn anti_tampering_leaves_a_probe_with_no_checked_value_in_place() {
    let src: &str = "var p = Function.prototype.toString(); check(p);";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::AntiTampering, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
    let s: &JscramblerTransformStats = stats_for(&out, JscramblerTransform::AntiTampering);
    assert_eq!((s.matched, s.skipped, s.reversed), (1, 1, 0));
}

#[test]
fn dead_objects_strips_underscored_decoy_decl_when_authorized() {
    let src: &str = "var __deadFoo = { a: 1, b: 2 }; var real = 5;";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::DeadObjects, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(!out.source.contains("__deadFoo"));
    assert!(out.source.contains("var real = 5"));
}

#[test]
fn dead_objects_detect_only_without_authorization() {
    let src: &str = "var __deadFoo = { a: 1 };";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::DeadObjects, false);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
    let s: &JscramblerTransformStats = stats_for(&out, JscramblerTransform::DeadObjects);
    assert!(s.matched >= 1);
    assert!(s.skipped >= 1);
}

#[test]
fn self_defending_strips_tostring_search_iife() {
    let src: &str =
        "(function(){var t = function(){return ('xy').toString().search('z');}; t();}());";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::SelfDefending, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(!out.source.contains("toString().search"));
}

#[test]
fn self_healing_strips_window_onerror_tamper_handler() {
    let src: &str = "var x = 1; window.onerror = function(e){ tamper(); };";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::SelfHealing, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(!out.source.contains("window.onerror"));
    assert!(out.source.contains("var x = 1"));
}

#[test]
fn self_healing_detect_only_without_authorization() {
    let src: &str = "window.onerror = function(e){ tamper(); };";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::SelfHealing, false);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
    let s: &JscramblerTransformStats = stats_for(&out, JscramblerTransform::SelfHealing);
    assert!(s.matched >= 1);
    assert!(s.skipped >= 1);
}

#[test]
fn rasp_strip_preserves_unrelated_statements() {
    let src: &str = "var a = 1; debugger; var b = 2;";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::AntiDebugging, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(out.source.contains("var a = 1"));
    assert!(out.source.contains("var b = 2"));
    assert!(!out.source.contains("debugger"));
}
