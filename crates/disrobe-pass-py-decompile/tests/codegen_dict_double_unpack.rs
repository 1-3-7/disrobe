#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn
)]

use disrobe_pass_py_decompile::ast::{ConstValue, Expr, ExprCtx, Keyword};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};

#[test]
fn dict_call_with_double_unpack_and_kw_emits_all_three_pieces() {
    let call: Expr = Expr::Call {
        func: Box::new(Expr::Name {
            id: "dict".to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }),
        args: Vec::new(),
        keywords: vec![
            Keyword {
                arg: None,
                value: Expr::Name {
                    id: "a".to_owned(),
                    ctx: ExprCtx::Load,
                    line: None,
                },
            },
            Keyword {
                arg: None,
                value: Expr::Name {
                    id: "b".to_owned(),
                    ctx: ExprCtx::Load,
                    line: None,
                },
            },
            Keyword {
                arg: Some("k".to_owned()),
                value: Expr::Constant {
                    value: ConstValue::Int(1),
                    line: None,
                },
            },
        ],
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&call, &v);
    assert_eq!(out, "dict(**a, **b, k=1)");
    assert!(out.matches("**").count() == 2);
    assert!(out.contains("k=1"));
}

#[test]
fn dict_literal_with_double_unpack_emits_braces() {
    let d: Expr = Expr::Dict {
        keys: vec![
            None,
            None,
            Some(Expr::Constant {
                value: ConstValue::Str("k".to_owned()),
                line: None,
            }),
        ],
        values: vec![
            Expr::Name {
                id: "a".to_owned(),
                ctx: ExprCtx::Load,
                line: None,
            },
            Expr::Name {
                id: "b".to_owned(),
                ctx: ExprCtx::Load,
                line: None,
            },
            Expr::Constant {
                value: ConstValue::Int(1),
                line: None,
            },
        ],
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&d, &v);
    assert_eq!(out, "{**a, **b, \"k\": 1}");
}
