#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{
    TerserRestoreReport, restore_terser_mangled as restore_terser_mangled_result,
};

fn restore_terser_mangled(source: &str) -> TerserRestoreReport {
    restore_terser_mangled_result(source).expect("fixture must be within the source limit")
}

#[test]
fn restores_short_function_name() {
    let src: &str = "function a(b){var c=b+1;return c;}";
    let r: TerserRestoreReport = restore_terser_mangled(src);
    assert!(r.identifiers_renamed > 0, "{r:?}");
    assert!(r.references_rewritten > 0);
}

#[test]
fn preserves_long_names_unchanged() {
    let src: &str = "function longName(){var alsoLong=1;return alsoLong;}";
    let r: TerserRestoreReport = restore_terser_mangled(src);
    assert_eq!(r.identifiers_renamed, 0);
    assert!(r.rewritten.contains("longName"));
    assert!(r.rewritten.contains("alsoLong"));
}

#[test]
fn does_not_touch_member_expressions() {
    let src: &str = "function f(){return obj.x;}";
    let r: TerserRestoreReport = restore_terser_mangled(src);
    assert!(
        r.rewritten.contains("obj.x"),
        "object property must survive: {r:?}"
    );
}

#[test]
fn handles_unparseable_source_gracefully() {
    let src: &str = "var = ;;; not valid @@@";
    let r: TerserRestoreReport = restore_terser_mangled(src);
    assert_eq!(r.rewritten, src);
    assert_eq!(r.identifiers_renamed, 0);
}
