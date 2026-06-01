#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use disrobe_pass_py_decompile::ast::{Stmt, TypeParam};
use disrobe_pass_py_decompile::codegen::type_params_emit::{
    emit_class_def_with_type_params, emit_function_def_with_type_params, emit_type_alias,
    emit_type_params, supports_pep_695, supports_pep_696,
};

use crate::common::{name, ver};

#[test]
fn pep_version_gates() {
    assert!(supports_pep_695(&ver(3, 12)));
    assert!(!supports_pep_695(&ver(3, 11)));
    assert!(supports_pep_696(&ver(3, 13)));
    assert!(!supports_pep_696(&ver(3, 12)));
}

#[test]
fn simple_typevar_renders() {
    let params: Vec<TypeParam> = vec![TypeParam::TypeVar {
        name: "T".to_owned(),
        bound: None,
        default: None,
    }];
    let out: String = emit_type_params(&params, &ver(3, 12));
    assert_eq!(out, "[T]");
}

#[test]
fn typevar_with_bound() {
    let params: Vec<TypeParam> = vec![TypeParam::TypeVar {
        name: "T".to_owned(),
        bound: Some(name("int")),
        default: None,
    }];
    let out: String = emit_type_params(&params, &ver(3, 12));
    assert_eq!(out, "[T: int]");
}

#[test]
fn typevar_with_default_pep_696() {
    let params: Vec<TypeParam> = vec![TypeParam::TypeVar {
        name: "T".to_owned(),
        bound: Some(name("int")),
        default: Some(name("int")),
    }];
    let out: String = emit_type_params(&params, &ver(3, 13));
    assert_eq!(out, "[T: int = int]");
}

#[test]
fn type_param_tuple_and_paramspec() {
    let params: Vec<TypeParam> = vec![
        TypeParam::TypeVarTuple {
            name: "Ts".to_owned(),
            default: None,
        },
        TypeParam::ParamSpec {
            name: "P".to_owned(),
            default: None,
        },
    ];
    let out: String = emit_type_params(&params, &ver(3, 12));
    assert_eq!(out, "[*Ts, **P]");
}

#[test]
fn function_def_with_type_params() {
    let params: Vec<TypeParam> = vec![TypeParam::TypeVar {
        name: "T".to_owned(),
        bound: None,
        default: None,
    }];
    let body: Vec<Stmt> = vec![Stmt::Return(Some(name("x")))];
    let out: String = emit_function_def_with_type_params(
        "f",
        &params,
        "x: T",
        Some(&name("T")),
        &body,
        &[],
        0,
        &ver(3, 12),
    );
    assert!(out.starts_with("def f[T](x: T) -> T:"), "got: {out}");
    assert!(out.contains("return x"), "got: {out}");
}

#[test]
fn class_def_with_type_params() {
    let params: Vec<TypeParam> = vec![
        TypeParam::TypeVar {
            name: "T".to_owned(),
            bound: None,
            default: None,
        },
        TypeParam::TypeVar {
            name: "U".to_owned(),
            bound: None,
            default: None,
        },
    ];
    let body: Vec<Stmt> = vec![Stmt::Pass];
    let out: String =
        emit_class_def_with_type_params("Container", &params, "", &body, &[], 0, &ver(3, 12));
    assert!(out.starts_with("class Container[T, U]:"), "got: {out}");
}

#[test]
fn type_alias_renders_pep_695() {
    let params: Vec<TypeParam> = vec![TypeParam::TypeVar {
        name: "T".to_owned(),
        bound: None,
        default: None,
    }];
    let out: String = emit_type_alias("Box", &params, &name("list"), 0, &ver(3, 12));
    assert_eq!(out, "type Box[T] = list");
}
