#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use disrobe_pass_py_decompile::ast::{ExceptHandler, Stmt};
use disrobe_pass_py_decompile::codegen::except_group_emit::{
    emit_try_star, supports_except_groups,
};

use crate::common::{name, ver};

#[test]
fn except_groups_version_gate() {
    assert!(supports_except_groups(&ver(3, 11)));
    assert!(!supports_except_groups(&ver(3, 10)));
}

#[test]
fn try_star_with_single_handler() {
    let body: Vec<Stmt> = vec![Stmt::Pass];
    let handlers: Vec<ExceptHandler> = vec![ExceptHandler {
        typ: Some(name("ValueError")),
        name: Some("eg".to_owned()),
        body: vec![Stmt::Pass],
        line: None,
    }];
    let out: String = emit_try_star(&body, &handlers, &[], &[], 0, &ver(3, 11));
    assert!(out.contains("try:"), "got: {out}");
    assert!(out.contains("except* ValueError as eg:"), "got: {out}");
}

#[test]
fn try_star_with_finally() {
    let body: Vec<Stmt> = vec![Stmt::Pass];
    let handlers: Vec<ExceptHandler> = vec![ExceptHandler {
        typ: Some(name("Exception")),
        name: None,
        body: vec![Stmt::Pass],
        line: None,
    }];
    let finalbody: Vec<Stmt> = vec![Stmt::Pass];
    let out: String = emit_try_star(&body, &handlers, &[], &finalbody, 0, &ver(3, 12));
    assert!(out.contains("except* Exception:"), "got: {out}");
    assert!(out.contains("finally:"), "got: {out}");
}
