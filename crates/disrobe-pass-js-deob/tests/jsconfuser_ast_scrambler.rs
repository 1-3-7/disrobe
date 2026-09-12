#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{AstScramblerResult, reverse_ast_scrambler};

#[test]
fn folds_right_leaning_associative_addition() {
    let src: &str = "var x = a + (b + c);";
    let r: AstScramblerResult = reverse_ast_scrambler(src);
    assert!(r.rotations_folded >= 1);
    assert!(r.rewritten_source.contains("(a + b) + c"));
}

#[test]
fn folds_right_leaning_xor_in_function_body() {
    let src: &str = "function masked(x, y, z){ return x ^ (y ^ z); }";
    let r: AstScramblerResult = reverse_ast_scrambler(src);
    assert!(r.rotations_folded >= 1);
    assert!(r.rewritten_source.contains("(x ^ y) ^ z"));
}

#[test]
fn folds_right_leaning_bitwise_or_in_if_test() {
    let src: &str = "if (p | (q | r)) doIt();";
    let r: AstScramblerResult = reverse_ast_scrambler(src);
    assert!(r.rotations_folded >= 1);
    assert!(r.rewritten_source.contains("(p | q) | r"));
}

#[test]
fn folds_right_leaning_multiplication_in_return_stmt() {
    let src: &str = "function area(){ return w * (h * d); }";
    let r: AstScramblerResult = reverse_ast_scrambler(src);
    assert!(r.rotations_folded >= 1);
    assert!(r.rewritten_source.contains("(w * h) * d"));
}

#[test]
fn leaves_left_leaning_canonical_form_alone() {
    let src: &str = "var z = (a + b) + c;";
    let r: AstScramblerResult = reverse_ast_scrambler(src);
    assert_eq!(r.rotations_folded, 0);
}

#[test]
fn leaves_subtraction_alone_because_non_associative() {
    let src: &str = "var v = a - (b - c);";
    let r: AstScramblerResult = reverse_ast_scrambler(src);
    assert_eq!(r.rotations_folded, 0);
    assert!(r.rewritten_source.contains("a - (b - c)"));
}
