#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{AtobIndirectionResult, peel_atob_indirection};

const SIMPLE: &str = include_str!("../corpus/esoteric/atob-indirection-simple.js");
const NESTED: &str = include_str!("../corpus/esoteric/atob-indirection-nested.js");

#[test]
fn folds_simple_atob_literal() {
    let res: AtobIndirectionResult = peel_atob_indirection(SIMPLE);
    assert!(res.stats.atob_calls_folded >= 1);
    assert!(res.rewritten.contains("\"Hello, disrobe!\""));
    assert!(res.recovered_payloads.iter().any(|p| p.contains("disrobe")));
}

#[test]
fn recursive_descent_unwraps_nested_atob() {
    let res: AtobIndirectionResult = peel_atob_indirection(NESTED);
    assert!(res.stats.atob_calls_folded >= 1);
    assert!(res.recovered_payloads.iter().any(|p| p.contains("atob")));
}

#[test]
fn btoa_literal_is_encoded() {
    let src: &str = r#"var x = btoa("Hello");"#;
    let res: AtobIndirectionResult = peel_atob_indirection(src);
    assert_eq!(res.stats.btoa_calls_folded, 1);
    assert!(res.rewritten.contains("\"SGVsbG8=\""));
}

#[test]
fn non_constant_atob_left_alone() {
    let src: &str = "var x = atob(input);";
    let res: AtobIndirectionResult = peel_atob_indirection(src);
    assert_eq!(res.stats.atob_calls_folded, 0);
}
