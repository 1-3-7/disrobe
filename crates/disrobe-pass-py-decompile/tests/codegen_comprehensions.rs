#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn
)]

use disrobe_pass_py_decompile::ast::{Comprehension, Expr, ExprCtx};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};

#[test]
fn list_comp_with_multi_for_and_if() {
    let comp1: Comprehension = Comprehension {
        target: name("x", ExprCtx::Store),
        iter: name("xs", ExprCtx::Load),
        ifs: vec![name("cond", ExprCtx::Load)],
        is_async: false,
    };
    let comp2: Comprehension = Comprehension {
        target: name("y", ExprCtx::Store),
        iter: name("ys", ExprCtx::Load),
        ifs: Vec::new(),
        is_async: false,
    };
    let e: Expr = Expr::ListComp {
        elt: Box::new(Expr::Tuple {
            elts: vec![name("x", ExprCtx::Load), name("y", ExprCtx::Load)],
            ctx: ExprCtx::Load,
        }),
        generators: vec![comp1, comp2],
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert_eq!(out, "[(x, y) for x in xs if cond for y in ys]");
}

#[test]
fn set_comp_emits_curly_braces() {
    let comp: Comprehension = Comprehension {
        target: name("x", ExprCtx::Store),
        iter: name("xs", ExprCtx::Load),
        ifs: Vec::new(),
        is_async: false,
    };
    let e: Expr = Expr::SetComp {
        elt: Box::new(name("x", ExprCtx::Load)),
        generators: vec![comp],
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert_eq!(out, "{x for x in xs}");
}

#[test]
fn dict_comp_emits_kv_form() {
    let comp: Comprehension = Comprehension {
        target: name("k", ExprCtx::Store),
        iter: name("m", ExprCtx::Load),
        ifs: Vec::new(),
        is_async: false,
    };
    let e: Expr = Expr::DictComp {
        key: Box::new(name("k", ExprCtx::Load)),
        value: Box::new(name("v", ExprCtx::Load)),
        generators: vec![comp],
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert_eq!(out, "{k: v for k in m}");
}

#[test]
fn generator_exp_wraps_in_parens() {
    let comp: Comprehension = Comprehension {
        target: name("x", ExprCtx::Store),
        iter: name("xs", ExprCtx::Load),
        ifs: Vec::new(),
        is_async: false,
    };
    let e: Expr = Expr::GeneratorExp {
        elt: Box::new(name("x", ExprCtx::Load)),
        generators: vec![comp],
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert_eq!(out, "(x for x in xs)");
}

#[test]
fn async_comprehension_emits_async_for() {
    let comp: Comprehension = Comprehension {
        target: name("x", ExprCtx::Store),
        iter: name("xs", ExprCtx::Load),
        ifs: Vec::new(),
        is_async: true,
    };
    let e: Expr = Expr::ListComp {
        elt: Box::new(name("x", ExprCtx::Load)),
        generators: vec![comp],
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert!(out.contains("async for"));
}

fn name(id: &str, ctx: ExprCtx) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx,
        line: None,
    }
}
