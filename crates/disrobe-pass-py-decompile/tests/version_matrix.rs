#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::default_trait_access
)]

use disrobe_pass_py_decompile::ast::{Arg, Arguments, AstModule, ConstValue, Expr, ExprCtx, Stmt};
use disrobe_pass_py_decompile::bytecode::opcode::BinOp;
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};

fn double_function() -> Stmt {
    Stmt::FunctionDef {
        name: "f".to_owned(),
        type_params: Vec::new(),
        args: Arguments {
            args: vec![Arg {
                arg: "x".to_owned(),
                annotation: None,
                default: None,
                line: None,
            }],
            ..Default::default()
        },
        body: vec![Stmt::Return(Some(Expr::BinOp {
            left: Box::new(Expr::Name {
                id: "x".to_owned(),
                ctx: ExprCtx::Load,
                line: None,
            }),
            op: BinOp::Mul,
            right: Box::new(Expr::Constant {
                value: ConstValue::Int(2),
                line: None,
            }),
        }))],
        decorators: Vec::new(),
        returns: None,
        is_async: false,
        docstring: None,
        line: None,
    }
}

fn module_for(stmt: Stmt) -> AstModule {
    AstModule {
        docstring: None,
        body: vec![stmt],
        blank_lines: Default::default(),
    }
}

fn render(module: &AstModule, version: &PyVersion) -> String {
    let em: DefaultEmitter = DefaultEmitter::new();
    em.emit_module(module, version)
}

#[test]
fn matrix_27_basic_function_renders() {
    let module: AstModule = module_for(double_function());
    let v: PyVersion = PyVersion::V2_7;
    let out: String = render(&module, &v);
    assert!(out.contains("def f(x):"), "2.7 def header: {out}");
    assert!(out.contains("return x * 2"), "2.7 return expr: {out}");
}

#[test]
fn matrix_36_fstring_supported_in_version_dispatch() {
    let module: AstModule = module_for(double_function());
    let v: PyVersion = PyVersion::V3_6;
    let out: String = render(&module, &v);
    assert!(out.contains("def f(x):"), "3.6 def header");
    assert!(out.contains("return x * 2"), "3.6 return expr");
    assert!(v.supports_fstring(), "3.6 capability flag");
}

#[test]
fn matrix_310_match_capability_flag_on() {
    let module: AstModule = module_for(double_function());
    let v: PyVersion = PyVersion::V3_10;
    let out: String = render(&module, &v);
    assert!(out.contains("def f(x):"), "3.10 def");
    assert!(out.contains("return x * 2"), "3.10 return");
    assert!(v.supports_match(), "3.10 must support match");
}

#[test]
fn matrix_311_except_star_capability_flag_on() {
    let module: AstModule = module_for(double_function());
    let v: PyVersion = PyVersion::V3_11;
    let out: String = render(&module, &v);
    assert!(out.contains("def f(x):"), "3.11 def");
    assert!(out.contains("return x * 2"), "3.11 return");
    assert!(v.supports_except_groups(), "3.11 except* capability");
    assert!(
        v.supports_zero_cost_exceptions(),
        "3.11 zero-cost exceptions"
    );
}

#[test]
fn matrix_312_pep_695_capability_flag_on() {
    let module: AstModule = module_for(double_function());
    let v: PyVersion = PyVersion::V3_12;
    let out: String = render(&module, &v);
    assert!(out.contains("def f(x):"), "3.12 def");
    assert!(out.contains("return x * 2"), "3.12 return");
    assert!(v.supports_pep_695(), "3.12 PEP-695 capability");
}

#[test]
fn matrix_313_pep_696_capability_flag_on() {
    let module: AstModule = module_for(double_function());
    let v: PyVersion = PyVersion::V3_13;
    let out: String = render(&module, &v);
    assert!(out.contains("def f(x):"), "3.13 def");
    assert!(out.contains("return x * 2"), "3.13 return");
    assert!(v.supports_pep_696(), "3.13 PEP-696 capability");
}

#[test]
fn matrix_314_tstring_capability_flag_on() {
    let module: AstModule = module_for(double_function());
    let v: PyVersion = PyVersion::V3_14;
    let out: String = render(&module, &v);
    assert!(out.contains("def f(x):"), "3.14 def");
    assert!(out.contains("return x * 2"), "3.14 return");
    assert!(v.supports_tstring(), "3.14 t-string capability");
}

#[test]
fn matrix_async_capability_only_36_plus() {
    assert!(!PyVersion::V2_7.supports_async(), "2.7 no async/await");
    assert!(PyVersion::V3_6.supports_async(), "3.6 async/await");
    assert!(PyVersion::V3_14.supports_async(), "3.14 async/await");
}

#[test]
fn matrix_word_code_only_36_plus() {
    assert!(!PyVersion::V2_7.supports_word_code(), "2.7 legacy bytecode");
    assert!(PyVersion::V3_6.supports_word_code(), "3.6+ wordcode");
}

#[test]
fn matrix_walrus_only_38_plus() {
    assert!(!PyVersion::V3_7.supports_walrus(), "3.7 no walrus");
    assert!(PyVersion::V3_8.supports_walrus(), "3.8+ walrus");
}

#[test]
fn matrix_all_seven_targeted_versions_render_consistently() {
    let module: AstModule = module_for(double_function());
    let versions: Vec<PyVersion> = vec![
        PyVersion::V2_7,
        PyVersion::V3_6,
        PyVersion::V3_10,
        PyVersion::V3_11,
        PyVersion::V3_12,
        PyVersion::V3_13,
        PyVersion::V3_14,
    ];
    let base: String = render(&module, &PyVersion::V3_12);
    for v in versions {
        let out: String = render(&module, &v);
        assert_eq!(
            out, base,
            "version {v:?} diverged from baseline emit for `def f(x): return x * 2`: got {out}"
        );
    }
}
