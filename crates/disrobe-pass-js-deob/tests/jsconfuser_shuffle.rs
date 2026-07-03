#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{ShuffleReversalResult, reverse_shuffle};

#[test]
fn restores_canonical_order_for_three_statement_block() {
    let src: &str = "var __ord = [2, 0, 1];\n(function () { var __stmts = [\"first()\", \"second()\", \"third()\"]; })();";
    let r: ShuffleReversalResult = reverse_shuffle(src);
    assert_eq!(r.blocks_reordered, 1);
    let out: &String = &r.rewritten_source;
    let p3: usize = out.find("third()").expect("third missing");
    let p1: usize = out.find("first()").expect("first missing");
    let p2: usize = out.find("second()").expect("second missing");
    assert!(p3 < p1 && p1 < p2, "wrong order: {out}");
}

#[test]
fn restores_canonical_order_for_five_statement_block() {
    let src: &str = "var __ord = [4, 2, 0, 3, 1];\n(function () { var __stmts = [\"a()\", \"b()\", \"c()\", \"d()\", \"e()\"]; })();";
    let r: ShuffleReversalResult = reverse_shuffle(src);
    assert_eq!(r.blocks_reordered, 1);
    let out: &String = &r.rewritten_source;
    let pe: usize = out.find("e()").expect("e missing");
    let pc: usize = out.find("c()").expect("c missing");
    let pa: usize = out.find("a()").expect("a missing");
    let pd: usize = out.find("d()").expect("d missing");
    let pb: usize = out.find("b()").expect("b missing");
    assert!(
        pe < pc && pc < pa && pa < pd && pd < pb,
        "wrong order: {out}"
    );
}

#[test]
fn rejects_when_order_length_mismatches_statement_count() {
    let src: &str =
        "var __ord = [1, 0];\n(function () { var __stmts = [\"a()\", \"b()\", \"c()\"]; })();";
    let r: ShuffleReversalResult = reverse_shuffle(src);
    assert_eq!(r.blocks_reordered, 0);
}

#[test]
fn rejects_non_permutation_orders() {
    let src: &str =
        "var __ord = [0, 0, 0];\n(function () { var __stmts = [\"a()\", \"b()\", \"c()\"]; })();";
    let r: ShuffleReversalResult = reverse_shuffle(src);
    assert_eq!(r.blocks_reordered, 0);
}

#[test]
fn leaves_unrelated_arrays_alone() {
    let src: &str = "var counts = [1, 2, 3, 4];\nuse(counts);";
    let r: ShuffleReversalResult = reverse_shuffle(src);
    assert_eq!(r.blocks_reordered, 0);
    assert_eq!(r.rewritten_source, src);
}
