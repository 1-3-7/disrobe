#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{StringEncodingResult, reverse_string_encoding};

#[test]
fn decodes_pure_hex_escape_run_into_ascii() {
    let src: &str = "var greeting = '\\x68\\x65\\x6c\\x6c\\x6f';";
    let r: StringEncodingResult = reverse_string_encoding(src);
    assert_eq!(r.literals_decoded, 1);
    assert!(r.rewritten_source.contains("'hello'"), "out: {r:?}");
}

#[test]
fn decodes_mixed_hex_and_unicode_escapes() {
    let src: &str = "var s = '\\x68\\x69 \\u0041\\u0042';";
    let r: StringEncodingResult = reverse_string_encoding(src);
    assert_eq!(r.literals_decoded, 1);
    assert!(r.rewritten_source.contains("'hi AB'"));
}

#[test]
fn decodes_unicode_code_point_curly_form() {
    let src: &str = "var s = '\\u{1F600} ok';";
    let r: StringEncodingResult = reverse_string_encoding(src);
    assert_eq!(r.literals_decoded, 1);
    assert!(r.rewritten_source.contains('\u{1F600}'));
}

#[test]
fn switches_to_double_quote_when_decoded_payload_contains_single_quote() {
    let src: &str = r"var s = '\x27pwned\x27';";
    let r: StringEncodingResult = reverse_string_encoding(src);
    assert_eq!(r.literals_decoded, 1);
    assert!(r.rewritten_source.contains("\"'pwned'\""), "out: {r:?}");
}

#[test]
fn leaves_clean_ascii_literals_alone() {
    let src: &str = "var s = 'already plain';";
    let r: StringEncodingResult = reverse_string_encoding(src);
    assert_eq!(r.literals_decoded, 0);
    assert_eq!(r.rewritten_source, src);
}
