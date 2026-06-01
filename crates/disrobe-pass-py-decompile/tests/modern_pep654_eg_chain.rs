#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use disrobe_pass_py_decompile::ast::{ExceptHandler, Stmt};
use disrobe_pass_py_decompile::codegen::except_group_emit::emit_try_star;

use crate::common::{name, ver};

#[test]
fn nested_except_star_groups() {
    let inner_handlers: Vec<ExceptHandler> = vec![ExceptHandler {
        typ: Some(name("KeyError")),
        name: Some("k".to_owned()),
        body: vec![Stmt::Pass],
        line: None,
    }];
    let inner: Stmt = Stmt::TryStar {
        body: vec![Stmt::Pass],
        handlers: inner_handlers,
        orelse: Vec::new(),
        finalbody: Vec::new(),
        line: None,
    };
    let outer_handlers: Vec<ExceptHandler> = vec![ExceptHandler {
        typ: Some(name("ValueError")),
        name: Some("v".to_owned()),
        body: vec![Stmt::Pass],
        line: None,
    }];
    let out: String = emit_try_star(&[inner], &outer_handlers, &[], &[], 0, &ver(3, 11));
    assert!(out.contains("try:"), "got: {out}");
    assert!(out.contains("except* ValueError as v:"), "got: {out}");
}

#[test]
fn except_star_chain_with_multiple_types() {
    let handlers: Vec<ExceptHandler> = vec![
        ExceptHandler {
            typ: Some(name("KeyError")),
            name: Some("k".to_owned()),
            body: vec![Stmt::Pass],
            line: None,
        },
        ExceptHandler {
            typ: Some(name("ValueError")),
            name: Some("v".to_owned()),
            body: vec![Stmt::Pass],
            line: None,
        },
        ExceptHandler {
            typ: Some(name("TypeError")),
            name: None,
            body: vec![Stmt::Pass],
            line: None,
        },
    ];
    let out: String = emit_try_star(&[Stmt::Pass], &handlers, &[], &[], 0, &ver(3, 12));
    assert!(out.contains("except* KeyError as k:"), "got: {out}");
    assert!(out.contains("except* ValueError as v:"), "got: {out}");
    assert!(out.contains("except* TypeError:"), "got: {out}");
}
