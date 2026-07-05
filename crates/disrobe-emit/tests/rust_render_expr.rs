#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items
)]

use disrobe_emit::rust::{
    RBinOp, binary, cast, int_dec, int_hex, method_call, parse_expr, path_expr, render_expr,
    signed_int, type_path, unsafe_block, var,
};

#[test]
fn render_expr_single_line_binary_needs_no_parens() {
    let expr: syn::Expr = binary(RBinOp::Add, var("a"), var("b"));
    assert_eq!(render_expr(&expr), "a + b");
}

#[test]
fn render_expr_inserts_parens_from_tree_structure() {
    let inner: syn::Expr = binary(RBinOp::Add, var("a"), var("b"));
    let outer: syn::Expr = binary(RBinOp::Mul, inner, var("c"));
    assert_eq!(render_expr(&outer), "(a + b) * c");
}

#[test]
fn render_expr_method_call_chain() {
    let expr: syn::Expr = method_call(var("a"), "wrapping_add", vec![var("b")]);
    assert_eq!(render_expr(&expr), "a.wrapping_add(b)");
}

#[test]
fn render_expr_cast_and_literal_suffix() {
    let expr: syn::Expr = cast(int_hex(0xff, "u64"), type_path("i64"));
    assert_eq!(render_expr(&expr), "0xffu64 as i64");
}

#[test]
fn render_expr_signed_negative_literal() {
    let expr: syn::Expr = signed_int(-8, "i64");
    assert_eq!(render_expr(&expr), "-8i64");
}

#[test]
fn render_expr_decimal_literal_suffix() {
    let expr: syn::Expr = int_dec(42, "u32");
    assert_eq!(render_expr(&expr), "42u32");
}

#[test]
fn render_expr_multi_segment_path_call() {
    let callee: syn::Expr = path_expr(&["core", "ptr", "read_unaligned"]);
    let expr: syn::Expr = disrobe_emit::rust::call(callee, vec![var("p")]);
    assert_eq!(render_expr(&expr), "core::ptr::read_unaligned(p)");
}

#[test]
fn render_expr_unsafe_block_wraps_single_expr() {
    let inner: syn::Expr = disrobe_emit::rust::call(var("f"), vec![var("x")]);
    let expr: syn::Expr = unsafe_block(inner);
    assert_eq!(render_expr(&expr), "unsafe { f(x) }");
}

#[test]
fn parse_expr_then_render_roundtrips_arbitrary_valid_source() {
    let parsed: syn::Expr = parse_expr("(a + b) * c").expect("valid rust expr");
    assert_eq!(render_expr(&parsed), "(a + b) * c");
}

#[test]
fn parse_expr_rejects_invalid_source() {
    assert!(parse_expr("a +").is_none());
}
