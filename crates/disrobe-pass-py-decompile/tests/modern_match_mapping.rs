#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use disrobe_pass_py_decompile::ast::{MatchCase, Pattern, Stmt};
use disrobe_pass_py_decompile::codegen::match_emit::emit_match;

use crate::common::{name, str_lit, ver};

#[test]
fn match_mapping_with_rest() {
    let pat: Pattern = Pattern::MatchMapping {
        keys: vec![str_lit("type")],
        patterns: vec![Pattern::MatchAs {
            pattern: None,
            name: Some("t".to_owned()),
        }],
        rest: Some("extra".to_owned()),
    };
    let cases: Vec<MatchCase> = vec![MatchCase {
        pattern: pat,
        guard: None,
        body: vec![Stmt::Pass],
    }];
    let out: String = emit_match(&name("payload"), &cases, 0, &ver(3, 12));
    assert!(out.contains("case {\"type\": t, **extra}:"), "got: {out}");
}

#[test]
fn match_mapping_no_rest() {
    let pat: Pattern = Pattern::MatchMapping {
        keys: vec![str_lit("k")],
        patterns: vec![Pattern::MatchAs {
            pattern: None,
            name: Some("v".to_owned()),
        }],
        rest: None,
    };
    let cases: Vec<MatchCase> = vec![MatchCase {
        pattern: pat,
        guard: None,
        body: vec![Stmt::Pass],
    }];
    let out: String = emit_match(&name("d"), &cases, 0, &ver(3, 10));
    assert!(out.contains("case {\"k\": v}:"), "got: {out}");
}
