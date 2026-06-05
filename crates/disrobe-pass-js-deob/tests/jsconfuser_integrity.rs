#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{IntegrityReversalResult, strip_integrity};

#[test]
fn strips_setinterval_self_hash_integrity_check() {
    let src: &str = "var n = 1;\nsetInterval(function () { if (boot.toString().replace(/\\s/g, '').length !== 1234) { window.location = 'about:blank'; } }, 1000);\nrun();";
    let r: IntegrityReversalResult = strip_integrity(src);
    assert_eq!(r.loops_stripped, 1);
    let out: &String = &r.rewritten_source;
    assert!(!out.contains("setInterval"), "loop leak: {out}");
    assert!(out.contains("run()"));
}

#[test]
fn strips_settimeout_self_hash_integrity_check() {
    let src: &str = "setTimeout(function(){ if(fn.toString().replace(/\\s/g,'').length !== 999) { throw new Error('tamper'); } }, 50);\nentry();";
    let r: IntegrityReversalResult = strip_integrity(src);
    assert_eq!(r.loops_stripped, 1);
    assert!(r.rewritten_source.contains("entry()"));
}

#[test]
fn strips_self_check_function_declaration_with_hash_keyword() {
    let src: &str = "function checkIntegrity(fn){ var hash = fn.toString().replace(/\\s/g, '').length; if (hash !== 999) throw new Error('integrity'); }\nuseit();";
    let r: IntegrityReversalResult = strip_integrity(src);
    assert!(r.loops_stripped >= 1, "stats: {r:?}");
    assert!(r.rewritten_source.contains("useit()"));
}

#[test]
fn strips_self_check_function_declaration_with_integrity_keyword() {
    let src: &str = "function verify(fn){ return fn.toString().replace(/\\s/g, '').length === integrity; }\nmain();";
    let r: IntegrityReversalResult = strip_integrity(src);
    assert!(r.loops_stripped >= 1);
    assert!(r.rewritten_source.contains("main()"));
}

#[test]
fn lossy_boundary_runtime_hash_value_documented() {
    let src: &str = "setInterval(function(){ if(boot.toString().replace(/\\s/g,'').length !== 4321) { debugger; } }, 250);\nproceed();";
    let r: IntegrityReversalResult = strip_integrity(src);
    assert_eq!(
        r.loops_stripped, 1,
        "lossy: the canonical hash constant (4321 here) encodes the original protected source's whitespace-stripped length and cannot be inverted; the protection wrapper is detected and removed so downstream passes see the payload, but the integrity hash itself is irretrievably runtime state",
    );
    assert!(r.rewritten_source.contains("proceed()"));
}

#[test]
fn leaves_normal_setinterval_alone() {
    let src: &str = "setInterval(function () { tick++; }, 1000);";
    let r: IntegrityReversalResult = strip_integrity(src);
    assert_eq!(r.loops_stripped, 0);
    assert_eq!(r.rewritten_source, src);
}
