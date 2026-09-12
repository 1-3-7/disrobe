#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::too_many_lines
)]

use disrobe_pass_py_decompile::ast::{Arg, Arguments, AstModule, ConstValue, Expr, ExprCtx, Stmt};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};

#[test]
fn simple_def_no_args() {
    let s: Stmt = Stmt::FunctionDef {
        name: "f".to_owned(),
        type_params: Vec::new(),
        args: Arguments::default(),
        body: vec![Stmt::Return(Some(int_expr(1)))],
        decorators: Vec::new(),
        returns: None,
        is_async: false,
        docstring: None,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "def f():\n    return 1");
}

#[test]
fn def_with_args_annotations_defaults() {
    let s: Stmt = Stmt::FunctionDef {
        name: "g".to_owned(),
        type_params: Vec::new(),
        args: Arguments {
            posonly: Vec::new(),
            args: vec![
                arg_with_ann("a", Some(name_expr("int", ExprCtx::Load))),
                arg_with_ann("b", Some(name_expr("int", ExprCtx::Load))),
            ],
            vararg: None,
            kwonly: Vec::new(),
            kw_defaults: Vec::new(),
            kwarg: None,
            defaults: vec![int_expr(0)],
        },
        body: vec![Stmt::Pass],
        decorators: Vec::new(),
        returns: Some(name_expr("int", ExprCtx::Load)),
        is_async: false,
        docstring: None,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "def g(a: int, b: int = 0) -> int:\n    pass");
}

#[test]
fn async_def_emits_async_keyword() {
    let s: Stmt = Stmt::FunctionDef {
        name: "h".to_owned(),
        type_params: Vec::new(),
        args: Arguments::default(),
        body: vec![Stmt::Pass],
        decorators: Vec::new(),
        returns: None,
        is_async: true,
        docstring: None,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert!(out.starts_with("async def h("));
}

#[test]
fn positional_only_uses_slash_marker_3_8_plus() {
    let s: Stmt = Stmt::FunctionDef {
        name: "p".to_owned(),
        type_params: Vec::new(),
        args: Arguments {
            posonly: vec![arg_plain("a"), arg_plain("b")],
            args: vec![arg_plain("c")],
            vararg: None,
            kwonly: Vec::new(),
            kw_defaults: Vec::new(),
            kwarg: None,
            defaults: Vec::new(),
        },
        body: vec![Stmt::Pass],
        decorators: Vec::new(),
        returns: None,
        is_async: false,
        docstring: None,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_8;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert!(out.contains("a, b, /, c"));
}

#[test]
fn nested_function_indents_correctly() {
    let inner: Stmt = Stmt::FunctionDef {
        name: "inner".to_owned(),
        type_params: Vec::new(),
        args: Arguments::default(),
        body: vec![Stmt::Return(Some(int_expr(2)))],
        decorators: Vec::new(),
        returns: None,
        is_async: false,
        docstring: None,
        line: None,
    };
    let outer: Stmt = Stmt::FunctionDef {
        name: "outer".to_owned(),
        type_params: Vec::new(),
        args: Arguments::default(),
        body: vec![inner],
        decorators: Vec::new(),
        returns: None,
        is_async: false,
        docstring: None,
        line: None,
    };
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![outer],
        blank_lines: std::collections::BTreeMap::new(),
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_module(&module, &v);
    assert!(out.contains("def outer():\n    def inner():\n        return 2"));
}

fn arg_plain(name: &str) -> Arg {
    Arg {
        arg: name.to_owned(),
        annotation: None,
        default: None,
        line: None,
    }
}

fn arg_with_ann(name: &str, ann: Option<Expr>) -> Arg {
    Arg {
        arg: name.to_owned(),
        annotation: ann.map(Box::new),
        default: None,
        line: None,
    }
}

fn int_expr(v: i128) -> Expr {
    Expr::Constant {
        value: ConstValue::Int(v),
        line: None,
    }
}

fn name_expr(id: &str, ctx: ExprCtx) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx,
        line: None,
    }
}
