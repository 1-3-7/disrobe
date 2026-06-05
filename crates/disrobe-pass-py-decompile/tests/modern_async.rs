#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use disrobe_pass_py_decompile::ast::{Arg, Arguments, Stmt, WithItem};
use disrobe_pass_py_decompile::codegen::async_emit::{
    emit_async_for, emit_async_function_def, emit_async_with, emit_await,
};

use crate::common::{int, name, name_store, ver};

fn arg(name: &str) -> Arg {
    Arg {
        arg: name.to_owned(),
        annotation: None,
        default: None,
        line: None,
    }
}

#[test]
fn async_def_renders() {
    let args: Arguments = Arguments {
        args: vec![arg("x")],
        ..Arguments::default()
    };
    let body: Vec<Stmt> = vec![Stmt::Return(Some(name("x")))];
    let out: String = emit_async_function_def("f", &[], &args, &body, &[], None, 0, &ver(3, 12));
    assert!(out.starts_with("async def f(x):"), "got: {out}");
    assert!(out.contains("return x"), "got: {out}");
}

#[test]
fn async_with_renders() {
    let items: Vec<WithItem> = vec![WithItem {
        context_expr: name("cm"),
        optional_vars: Some(name_store("c")),
    }];
    let body: Vec<Stmt> = vec![Stmt::Pass];
    let out: String = emit_async_with(&items, &body, 0, &ver(3, 10));
    assert!(out.starts_with("async with cm as c:"), "got: {out}");
}

#[test]
fn async_for_with_else() {
    let body: Vec<Stmt> = vec![Stmt::Pass];
    let orelse: Vec<Stmt> = vec![Stmt::Pass];
    let out: String = emit_async_for(
        &name_store("i"),
        &name("xs"),
        &body,
        &orelse,
        0,
        &ver(3, 12),
    );
    assert!(out.starts_with("async for i in xs:"), "got: {out}");
    assert!(out.contains("\nelse:"), "got: {out}");
}

#[test]
fn await_expr_renders() {
    let out: String = emit_await(&name("coro"), &ver(3, 11));
    assert_eq!(out, "await coro");
}

#[test]
fn async_for_no_else_has_no_else_branch() {
    let body: Vec<Stmt> = vec![Stmt::Expr(int(0))];
    let out: String = emit_async_for(&name_store("k"), &name("ks"), &body, &[], 0, &ver(3, 12));
    assert!(!out.contains("else:"), "got: {out}");
}
