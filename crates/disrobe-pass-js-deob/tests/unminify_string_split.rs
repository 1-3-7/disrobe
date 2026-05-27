#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{UnminifyStats, unminify};

#[test]
fn unminify_picks_up_string_split_chain() {
    let src: &str = r#"var msg = "hel" + "lo" + " " + "world";"#;
    let (out, stats): (String, UnminifyStats) = unminify(src);
    assert!(
        stats.string_split_literals_merged >= 3,
        "expected ≥3 merges across chain of 4 literals; got {}",
        stats.string_split_literals_merged
    );
    assert!(
        out.contains("'hello world'"),
        "expected fully merged literal; got: {out}"
    );
}

#[test]
fn unminify_skips_template_interpolation() {
    let src: &str = r#"var greet = `${"hi"}`; var combo = "a" + "b";"#;
    let (out, stats): (String, UnminifyStats) = unminify(src);
    assert!(
        stats.string_split_literals_merged >= 1,
        "regular chain must still fold"
    );
    assert!(
        out.contains("`${\"hi\"}`"),
        "template-literal must be preserved: {out}"
    );
    assert!(
        out.contains("'ab'"),
        "outside-template chain must fold: {out}"
    );
}

#[test]
fn unminify_real_world_obfuscator_style() {
    let src: &str = r#"function build() {
    var url = "https://" + "example.com" + "/" + "api" + "/" + "v1";
    var key = "secret_" + "token_" + "value";
    return { u: url, k: key };
}"#;
    let (out, stats): (String, UnminifyStats) = unminify(src);
    assert!(stats.string_split_literals_merged >= 7, "stats: {stats:?}");
    assert!(
        out.contains("'https://example.com/api/v1'"),
        "url merged: {out}"
    );
    assert!(out.contains("'secret_token_value'"), "key merged: {out}");
}

#[test]
fn unminify_leaves_non_literal_concat_untouched() {
    let src: &str = r#"var s = "a" + name + "b"; var t = "c" + 1 + "d";"#;
    let (out, stats): (String, UnminifyStats) = unminify(src);
    assert_eq!(
        stats.string_split_literals_merged, 0,
        "non-literal operands must not fold"
    );
    assert!(out.contains("\"a\" + name + \"b\"") || out.contains("'a' + name + 'b'"));
}
