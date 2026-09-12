#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn,
    clippy::items_after_statements
)]

use disrobe_pass_py_decompile::ast::{Arguments, ConstValue, Expr, ExprCtx, Stmt};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};

#[test]
fn simple_class_no_bases() {
    let s: Stmt = Stmt::ClassDef {
        name: "C".to_owned(),
        type_params: Vec::new(),
        bases: Vec::new(),
        keywords: Vec::new(),
        body: vec![Stmt::Pass],
        decorators: Vec::new(),
        docstring: None,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "class C:\n    pass");
}

#[test]
fn multiple_inheritance_preserves_base_order() {
    let s: Stmt = Stmt::ClassDef {
        name: "D".to_owned(),
        type_params: Vec::new(),
        bases: vec![name_expr("Alpha"), name_expr("Beta"), name_expr("Gamma")],
        keywords: Vec::new(),
        body: vec![Stmt::Pass],
        decorators: Vec::new(),
        docstring: None,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    let head: &str = out.lines().next().unwrap();
    let alpha_pos: usize = head.find("Alpha").unwrap();
    let beta_pos: usize = head.find("Beta").unwrap();
    let gamma_pos: usize = head.find("Gamma").unwrap();
    assert!(alpha_pos < beta_pos);
    assert!(beta_pos < gamma_pos);
    assert_eq!(head, "class D(Alpha, Beta, Gamma):");
}

#[test]
fn class_with_decorator() {
    let s: Stmt = Stmt::ClassDef {
        name: "C".to_owned(),
        type_params: Vec::new(),
        bases: Vec::new(),
        keywords: Vec::new(),
        body: vec![Stmt::Pass],
        decorators: vec![name_expr("dataclass")],
        docstring: None,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "@dataclass\nclass C:\n    pass");
}

#[test]
fn class_with_body_methods_and_nested() {
    let method: Stmt = Stmt::FunctionDef {
        name: "m".to_owned(),
        type_params: Vec::new(),
        args: Arguments {
            posonly: Vec::new(),
            args: vec![disrobe_pass_py_decompile::ast::Arg {
                arg: "self".to_owned(),
                annotation: None,
                default: None,
                line: None,
            }],
            vararg: None,
            kwonly: Vec::new(),
            kw_defaults: Vec::new(),
            kwarg: None,
            defaults: Vec::new(),
        },
        body: vec![Stmt::Return(Some(int_expr(0)))],
        decorators: Vec::new(),
        returns: None,
        is_async: false,
        docstring: None,
        line: None,
    };
    let s: Stmt = Stmt::ClassDef {
        name: "Outer".to_owned(),
        type_params: Vec::new(),
        bases: Vec::new(),
        keywords: Vec::new(),
        body: vec![method],
        decorators: Vec::new(),
        docstring: None,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "class Outer:\n    def m(self):\n        return 0");
}

fn int_expr(v: i128) -> Expr {
    Expr::Constant {
        value: ConstValue::Int(v),
        line: None,
    }
}

fn name_expr(id: &str) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    }
}
