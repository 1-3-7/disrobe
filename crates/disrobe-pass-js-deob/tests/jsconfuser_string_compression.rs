#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{StringCompressionResult, reverse_string_compression};

#[test]
fn expands_split_string_dictionary_into_array_literal() {
    let src: &str = "var dict = 'alpha|beta|gamma'.split('|');\nuse(dict[1]);";
    let r: StringCompressionResult = reverse_string_compression(src);
    assert_eq!(r.blocks_reversed, 1);
    assert!(
        r.rewritten_source
            .contains("[\"alpha\", \"beta\", \"gamma\"]"),
        "out: {r:?}"
    );
}

#[test]
fn folds_fromcharcode_run_into_string_literal() {
    let src: &str = "var greeting = String.fromCharCode(104, 101, 108, 108, 111);";
    let r: StringCompressionResult = reverse_string_compression(src);
    assert_eq!(r.blocks_reversed, 1);
    assert!(r.rewritten_source.contains("\"hello\""));
}

#[test]
fn handles_double_character_separator_in_split_dict() {
    let src: &str = "var parts = 'fooABbarABbaz'.split('AB');\nuse(parts);";
    let r: StringCompressionResult = reverse_string_compression(src);
    assert_eq!(r.blocks_reversed, 1);
    assert!(r.rewritten_source.contains("[\"foo\", \"bar\", \"baz\"]"));
}

#[test]
fn combined_split_and_fromcharcode_in_single_source() {
    let src: &str = "var a = 'x|y|z'.split('|');\nvar b = String.fromCharCode(65, 66, 67);";
    let r: StringCompressionResult = reverse_string_compression(src);
    assert_eq!(r.blocks_reversed, 2);
    assert!(r.rewritten_source.contains("[\"x\", \"y\", \"z\"]"));
    assert!(r.rewritten_source.contains("\"ABC\""));
}

#[test]
fn ignores_split_call_that_is_not_a_dictionary_decl() {
    let src: &str = "userInput.split(',');";
    let r: StringCompressionResult = reverse_string_compression(src);
    assert_eq!(r.blocks_reversed, 0);
    assert_eq!(r.rewritten_source, src);
}
