#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;

use disrobe_pass_js_deob::{
    CodeLockKind, Error, JscramblerDetection, JscramblerOptions, JscramblerOutput,
    JscramblerTransform, JscramblerTransformOpts, JscramblerTransformOutput,
    JscramblerTransformStats, deobfuscate_jscrambler, deobfuscate_jscrambler_transform_strict,
    detect_jscrambler_full,
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
fn browser_lock_detect_only_default_reports_match_and_preserves_source() {
    let src: &str = "if (navigator.userAgent.indexOf('Chrome') !== -1) { run(); }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::BrowserLock, false);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
    let s: &JscramblerTransformStats = stats_for(&out, JscramblerTransform::BrowserLock);
    assert!(s.matched >= 1);
    assert!(s.skipped >= 1);
    assert_eq!(s.reversed, 0);
}

#[test]
fn browser_lock_bypass_with_authorization_rewrites_guard_to_true() {
    let src: &str = "if (navigator.userAgent.indexOf('Chrome') !== -1) { run(); }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::BrowserLock, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(out.source.contains("if (true)"));
}

#[test]
fn browser_lock_detection_classifies_kind_browser() {
    let src: &str = "if (navigator.userAgent.indexOf('Chrome') !== -1) { run(); }";
    let det: JscramblerDetection = detect_jscrambler_full(src);
    assert!(det.code_locks.contains(&CodeLockKind::Browser));
}

#[test]
fn browser_lock_strict_requires_authorization() {
    let err: Error = deobfuscate_jscrambler_transform_strict(
        JscramblerTransform::BrowserLock,
        "if (navigator.userAgent.indexOf('Chrome') !== -1) { run(); }",
        &JscramblerTransformOpts::default(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::AuthorizationRequired { .. }));
}

#[test]
fn date_lock_detect_only_default_preserves_source() {
    let src: &str = "if (Date.now() > 1735689600000) { stop(); }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::DateLock, false);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
    let s: &JscramblerTransformStats = stats_for(&out, JscramblerTransform::DateLock);
    assert!(s.matched >= 1);
    assert!(s.skipped >= 1);
}

#[test]
fn date_lock_bypass_with_authorization_rewrites_guard_to_true() {
    let src: &str = "if (Date.now() > 1735689600000) { stop(); }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::DateLock, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(out.source.contains("if (true)"));
}

#[test]
fn date_lock_detects_new_date_get_time_form() {
    let src: &str = "if (new Date().getTime() > 1735689600000) { stop(); }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::DateLock, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(out.source.contains("if (true)"));
}

#[test]
fn date_lock_detects_get_full_year_form() {
    let src: &str = "if (new Date().getFullYear() > 2025) { stop(); }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::DateLock, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(out.source.contains("if (true)"));
}

#[test]
fn date_lock_strict_requires_authorization() {
    let err: Error = deobfuscate_jscrambler_transform_strict(
        JscramblerTransform::DateLock,
        "if (Date.now() > 1) { stop(); }",
        &JscramblerTransformOpts::default(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::AuthorizationRequired { .. }));
}

#[test]
fn domain_lock_detect_only_default_preserves_source() {
    let src: &str = "if (location.hostname !== 'example.com') { stop(); }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::DomainLock, false);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
    let s: &JscramblerTransformStats = stats_for(&out, JscramblerTransform::DomainLock);
    assert!(s.matched >= 1);
    assert!(s.skipped >= 1);
}

#[test]
fn domain_lock_bypass_with_authorization_rewrites_guard_to_true() {
    let src: &str = "if (location.hostname !== 'example.com') { stop(); }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::DomainLock, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(out.source.contains("if (true)"));
}

#[test]
fn domain_lock_detects_window_location_hostname_form_neutralizes_guard() {
    let src: &str = "if (window.location.hostname !== 'x.com') { stop(); }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::DomainLock, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(out.source.contains("true"));
    assert!(!out.source.contains("hostname !=="));
}

#[test]
fn domain_lock_detects_document_domain_form() {
    let src: &str = "if (document.domain !== 'x.com') { stop(); }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::DomainLock, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(out.source.contains("if (true)"));
}

#[test]
fn domain_lock_strict_requires_authorization() {
    let err: Error = deobfuscate_jscrambler_transform_strict(
        JscramblerTransform::DomainLock,
        "if (location.hostname !== 'x') { y(); }",
        &JscramblerTransformOpts::default(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::AuthorizationRequired { .. }));
}

#[test]
fn os_lock_detect_only_default_preserves_source() {
    let src: &str = "if (navigator.platform !== 'Win32') { stop(); }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::OsLock, false);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src);
    let s: &JscramblerTransformStats = stats_for(&out, JscramblerTransform::OsLock);
    assert!(s.matched >= 1);
    assert!(s.skipped >= 1);
}

#[test]
fn os_lock_bypass_with_authorization_rewrites_guard_to_true() {
    let src: &str = "if (navigator.platform !== 'Win32') { stop(); }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::OsLock, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(out.source.contains("if (true)"));
}

#[test]
fn os_lock_detects_navigator_oscpu_form() {
    let src: &str = "if (navigator.oscpu !== 'Windows NT 10.0') { stop(); }";
    let opts: JscramblerOptions = opts_with(JscramblerTransform::OsLock, true);
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(out.source.contains("if (true)"));
}

#[test]
fn os_lock_strict_requires_authorization() {
    let err: Error = deobfuscate_jscrambler_transform_strict(
        JscramblerTransform::OsLock,
        "if (navigator.platform !== 'Win32') { stop(); }",
        &JscramblerTransformOpts::default(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::AuthorizationRequired { .. }));
}

#[test]
fn lock_chain_runs_all_four_locks_detect_only_without_authorization() {
    let src: &str = concat!(
        "if (navigator.userAgent.indexOf('Chrome') !== -1) { run(); } ",
        "if (Date.now() > 1) { stop(); } ",
        "if (location.hostname !== 'x.com') { stop(); } ",
        "if (navigator.platform !== 'Win32') { stop(); }"
    );
    let mut set: BTreeSet<JscramblerTransform> = BTreeSet::new();
    set.insert(JscramblerTransform::BrowserLock);
    set.insert(JscramblerTransform::DateLock);
    set.insert(JscramblerTransform::DomainLock);
    set.insert(JscramblerTransform::OsLock);
    let opts: JscramblerOptions = JscramblerOptions {
        i_have_authorization: false,
        transforms: set,
    };
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert_eq!(out.source, src, "detect-only must not rewrite locks");
    assert_eq!(out.per_transform.len(), 4);
    for (_, s) in &out.per_transform {
        assert!(s.matched >= 1);
        assert!(s.skipped >= 1);
    }
}

#[test]
fn lock_chain_bypasses_all_four_locks_with_authorization() {
    let src: &str = concat!(
        "if (navigator.userAgent.indexOf('Chrome') !== -1) { run(); } ",
        "if (Date.now() > 1) { stop(); } ",
        "if (location.hostname !== 'x.com') { stop(); } ",
        "if (navigator.platform !== 'Win32') { stop(); }"
    );
    let mut set: BTreeSet<JscramblerTransform> = BTreeSet::new();
    set.insert(JscramblerTransform::BrowserLock);
    set.insert(JscramblerTransform::DateLock);
    set.insert(JscramblerTransform::DomainLock);
    set.insert(JscramblerTransform::OsLock);
    let opts: JscramblerOptions = JscramblerOptions {
        i_have_authorization: true,
        transforms: set,
    };
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    let true_count: usize = out.source.matches("if (true)").count();
    assert_eq!(true_count, 4, "all four guards must be rewritten to true");
}

#[test]
fn lock_strict_dispatch_accepts_all_four_with_authorization() {
    let src: &str = "var x = 1;";
    let opts: JscramblerTransformOpts = JscramblerTransformOpts {
        i_have_authorization: true,
    };
    for t in [
        JscramblerTransform::BrowserLock,
        JscramblerTransform::DateLock,
        JscramblerTransform::DomainLock,
        JscramblerTransform::OsLock,
    ] {
        let res: Result<JscramblerTransformOutput, _> =
            deobfuscate_jscrambler_transform_strict(t, src, &opts);
        assert!(res.is_ok(), "{t:?} must succeed when authorized");
    }
}
