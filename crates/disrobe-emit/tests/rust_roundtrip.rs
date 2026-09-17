#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::pedantic,
    clippy::nursery
)]

use disrobe_emit::rust::builder::{RBinOp, RUnOp};
use disrobe_emit::rust::{
    binary, call, cast, field, file, function, index, int, reference, render, trailing_expr,
    type_path, unary, var,
};
use proptest::prelude::*;
use syn::fold::Fold;

struct StripParens;

impl Fold for StripParens {
    fn fold_expr(&mut self, expr: syn::Expr) -> syn::Expr {
        let folded: syn::Expr = syn::fold::fold_expr(self, expr);
        match folded {
            syn::Expr::Paren(inner) => *inner.expr,
            syn::Expr::Group(inner) => *inner.expr,
            other => other,
        }
    }
}

fn strip(file: syn::File) -> syn::File {
    Fold::fold_file(&mut StripParens, file)
}

fn wrap(expr: syn::Expr) -> syn::File {
    file(vec![function(
        "probe",
        Vec::new(),
        None,
        vec![trailing_expr(expr)],
    )])
}

fn arb_bin_op() -> impl Strategy<Value = RBinOp> {
    prop::sample::select(vec![
        RBinOp::Add,
        RBinOp::Sub,
        RBinOp::Mul,
        RBinOp::Div,
        RBinOp::Rem,
        RBinOp::BitAnd,
        RBinOp::BitOr,
        RBinOp::BitXor,
        RBinOp::Shl,
        RBinOp::Shr,
        RBinOp::And,
        RBinOp::Or,
    ])
}

fn arb_var() -> impl Strategy<Value = String> {
    prop::sample::select(vec!["a", "b", "c", "d", "e"]).prop_map(str::to_owned)
}

fn arb_type() -> impl Strategy<Value = String> {
    prop::sample::select(vec!["u64", "i64", "u32", "i32", "usize"]).prop_map(str::to_owned)
}

fn arb_expr() -> impl Strategy<Value = syn::Expr> {
    let leaf = prop_oneof![
        (0u64..1000).prop_map(int),
        arb_var().prop_map(|name: String| var(&name)),
    ];
    leaf.prop_recursive(6, 192, 4, |inner: BoxedStrategy<syn::Expr>| {
        prop_oneof![
            (arb_bin_op(), inner.clone(), inner.clone())
                .prop_map(|(op, lhs, rhs): (RBinOp, syn::Expr, syn::Expr)| binary(op, lhs, rhs)),
            (
                prop::sample::select(vec![RUnOp::Neg, RUnOp::Not, RUnOp::Deref]),
                inner.clone()
            )
                .prop_map(|(op, operand): (RUnOp, syn::Expr)| unary(op, operand)),
            (any::<bool>(), inner.clone())
                .prop_map(|(mutable, operand): (bool, syn::Expr)| reference(mutable, operand)),
            (inner.clone(), arb_type())
                .prop_map(|(operand, ty): (syn::Expr, String)| cast(operand, type_path(&ty))),
            (arb_var(), prop::collection::vec(inner.clone(), 0..3))
                .prop_map(|(name, args): (String, Vec<syn::Expr>)| call(var(&name), args)),
            (inner.clone(), arb_var())
                .prop_map(|(base, name): (syn::Expr, String)| field(base, &name)),
            (arb_var(), inner).prop_map(|(name, idx): (String, syn::Expr)| index(var(&name), idx)),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn render_reparse_is_a_fixpoint(expr in arb_expr()) {
        let unit: syn::File = wrap(expr);
        let first: String = render(&unit);
        let tokens: proc_macro2::TokenStream = first
            .parse()
            .unwrap_or_else(|err| panic!("lex failed: {err} for {first:?}"));
        let reparsed: syn::File = syn::parse2(tokens)
            .unwrap_or_else(|err| panic!("parse failed: {err} for {first:?}"));
        let second: String = render(&reparsed);
        prop_assert_eq!(first, second);
    }

    #[test]
    fn render_reparse_preserves_tree(expr in arb_expr()) {
        let unit: syn::File = wrap(expr);
        let rendered: String = render(&unit);
        let tokens: proc_macro2::TokenStream = rendered.parse().expect("lex");
        let reparsed: syn::File = syn::parse2(tokens).expect("parse");
        prop_assert_eq!(strip(unit), strip(reparsed));
    }
}
