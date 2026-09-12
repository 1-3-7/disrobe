#![allow(clippy::unwrap_used, clippy::panic, clippy::pedantic)]

use disrobe_pass_beam::{Term, erlang_abstract};

fn var(name: &str) -> Term {
    Term::Tuple(vec![
        Term::Atom("var".to_owned()),
        Term::SmallInt(0),
        Term::Atom(name.to_owned()),
    ])
}

fn int(v: u8) -> Term {
    Term::Tuple(vec![
        Term::Atom("integer".to_owned()),
        Term::SmallInt(0),
        Term::SmallInt(v),
    ])
}

fn binop(op: &str, lhs: Term, rhs: Term) -> Term {
    Term::Tuple(vec![
        Term::Atom("op".to_owned()),
        Term::SmallInt(0),
        Term::Atom(op.to_owned()),
        lhs,
        rhs,
    ])
}

fn unop(op: &str, arg: Term) -> Term {
    Term::Tuple(vec![
        Term::Atom("op".to_owned()),
        Term::SmallInt(0),
        Term::Atom(op.to_owned()),
        arg,
    ])
}

fn render_expr(expr: Term) -> String {
    let clause: Term = Term::Tuple(vec![
        Term::Atom("clause".to_owned()),
        Term::SmallInt(0),
        Term::Nil,
        Term::Nil,
        Term::List {
            elements: vec![expr],
            tail: Box::new(Term::Nil),
        },
    ]);
    let rendered: String = erlang_abstract::render_function("f", &[clause]);
    rendered
        .lines()
        .find_map(|l: &str| {
            l.strip_prefix("    ")
                .map(|s: &str| s.trim_end_matches(['.', ',']).to_owned())
        })
        .unwrap_or_default()
}

#[test]
fn additive_right_operand_of_same_precedence_is_parenthesized() {
    let expr: Term = binop("-", var("X"), binop("-", var("Y"), var("Z")));
    assert_eq!(render_expr(expr), "X - (Y - Z)");
}

#[test]
fn multiplicative_right_operand_of_same_precedence_is_parenthesized() {
    let expr: Term = binop("div", int(64), binop("div", int(8), int(2)));
    assert_eq!(render_expr(expr), "64 div (8 div 2)");
}

#[test]
fn lower_precedence_right_operand_under_multiplication_is_parenthesized() {
    let expr: Term = binop("*", var("X"), binop("+", var("Y"), var("Z")));
    assert_eq!(render_expr(expr), "X * (Y + Z)");
}

#[test]
fn shift_right_operand_holds_added_operand() {
    let expr: Term = binop("bsl", int(1), binop("+", int(2), int(3)));
    assert_eq!(render_expr(expr), "1 bsl (2 + 3)");
}

#[test]
fn band_left_operand_of_bor_is_parenthesized() {
    let expr: Term = binop("band", binop("bor", int(1), int(2)), int(3));
    assert_eq!(render_expr(expr), "(1 bor 2) band 3");
}

#[test]
fn left_associative_chains_stay_unparenthesized_on_the_left() {
    let expr: Term = binop("-", binop("-", var("X"), var("Y")), var("Z"));
    assert_eq!(render_expr(expr), "X - Y - Z");
}

#[test]
fn addition_under_multiplication_left_operand_is_parenthesized() {
    let expr: Term = binop("*", binop("+", var("X"), var("Y")), var("Z"));
    assert_eq!(render_expr(expr), "(X + Y) * Z");
}

#[test]
fn nested_unary_minus_does_not_merge_into_a_list_subtraction_token() {
    let expr: Term = unop("-", unop("-", var("A")));
    let rendered: String = render_expr(expr);
    assert!(
        !rendered.contains("--"),
        "nested unary minus must not emit the -- token: {rendered}"
    );
}

#[test]
fn comparison_operand_that_is_a_comparison_is_parenthesized() {
    let expr: Term = binop("==", binop("<", var("A"), var("B")), var("C"));
    assert_eq!(render_expr(expr), "(A < B) == C");
}
