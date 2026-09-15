#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn
)]

use disrobe_pass_py_decompile::ast::{Expr, ExprCtx, Stmt, WithItem};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};

#[test]
fn single_with_item() {
    let s: Stmt = Stmt::With {
        items: vec![WithItem {
            context_expr: name("cm", ExprCtx::Load),
            optional_vars: Some(name("c", ExprCtx::Store)),
        }],
        body: vec![Stmt::Pass],
        is_async: false,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_10;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "with cm as c:\n    pass");
}

#[test]
fn multiple_with_items_single_with_line() {
    let s: Stmt = Stmt::With {
        items: vec![
            WithItem {
                context_expr: name("a", ExprCtx::Load),
                optional_vars: Some(name("x", ExprCtx::Store)),
            },
            WithItem {
                context_expr: name("b", ExprCtx::Load),
                optional_vars: Some(name("y", ExprCtx::Store)),
            },
            WithItem {
                context_expr: name("c", ExprCtx::Load),
                optional_vars: Some(name("z", ExprCtx::Store)),
            },
        ],
        body: vec![Stmt::Pass],
        is_async: false,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_10;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "with a as x, b as y, c as z:\n    pass");
    let nested_with_count: usize = out.matches("with ").count();
    assert_eq!(
        nested_with_count, 1,
        "multiple items emit as one `with` line, not nested"
    );
}

#[test]
fn nested_with_emits_inner_block() {
    let inner: Stmt = Stmt::With {
        items: vec![WithItem {
            context_expr: name("b", ExprCtx::Load),
            optional_vars: None,
        }],
        body: vec![Stmt::Pass],
        is_async: false,
        line: None,
    };
    let outer: Stmt = Stmt::With {
        items: vec![WithItem {
            context_expr: name("a", ExprCtx::Load),
            optional_vars: None,
        }],
        body: vec![inner],
        is_async: false,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_10;
    let out: String = em.emit_stmt(&outer, 0, &v);
    assert_eq!(out, "with a:\n    with b:\n        pass");
}

fn name(id: &str, ctx: ExprCtx) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx,
        line: None,
    }
}
