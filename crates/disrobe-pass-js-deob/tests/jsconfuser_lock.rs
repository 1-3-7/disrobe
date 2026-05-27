#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{LockReversalResult, strip_locks};

#[test]
fn strips_domain_lock_with_hostname_guard() {
    let src: &str = "function boot(){\n  if (window.location.hostname !== 'attacker.com') { return; }\n  doStuff();\n}";
    let r: LockReversalResult = strip_locks(src);
    assert_eq!(r.guards_stripped, 1);
    let out: &String = &r.rewritten_source;
    assert!(!out.contains("attacker.com"));
    assert!(out.contains("doStuff()"));
}

#[test]
fn strips_iframe_top_lock_self_neq_top_guard() {
    let src: &str = "function start(){\n  if (self !== window.top) { window.location = 'about:blank'; }\n  run();\n}";
    let r: LockReversalResult = strip_locks(src);
    assert_eq!(r.guards_stripped, 1);
    assert!(r.rewritten_source.contains("run()"));
}

#[test]
fn strips_date_lock_with_new_date_compare() {
    let src: &str =
        "if (new Date().getTime() > 1700000000000) { throw new Error('expired'); }\nproceed();";
    let r: LockReversalResult = strip_locks(src);
    assert!(r.guards_stripped >= 1, "stats: {r:?}");
    assert!(r.rewritten_source.contains("proceed()"));
}

#[test]
fn strips_anti_devtools_debugger_guard() {
    let src: &str =
        "if (new Date().getTime() - t > 100) { debugger; while (true) {} }\ncontinueMain();";
    let r: LockReversalResult = strip_locks(src);
    assert!(r.guards_stripped >= 1);
    assert!(r.rewritten_source.contains("continueMain()"));
}

#[test]
fn lossy_boundary_runtime_state_inversion_documented() {
    let src: &str =
        "function gate(){\n  if (navigator.userAgent !== 'chrome') { return; }\n  payload();\n}";
    let r: LockReversalResult = strip_locks(src);
    assert_eq!(
        r.guards_stripped, 1,
        "lossy: original runtime hostname / userAgent / Date.now() values cannot be recovered, but the guard wrapper itself is detected and removed so analysis can proceed against the payload",
    );
    assert!(r.rewritten_source.contains("payload()"));
    assert!(!r.rewritten_source.contains("navigator.userAgent"));
}

#[test]
fn leaves_unrelated_branches_alone() {
    let src: &str = "if (counter > 10) { console.log('over'); }";
    let r: LockReversalResult = strip_locks(src);
    assert_eq!(r.guards_stripped, 0);
    assert_eq!(r.rewritten_source, src);
}
