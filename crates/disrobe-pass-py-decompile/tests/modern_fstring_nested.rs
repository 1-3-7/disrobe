#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use disrobe_pass_py_decompile::ast::{Expr, FormatConversion};
use disrobe_pass_py_decompile::codegen::fstring_emit::{emit_fstring, supports_pep_701};

use crate::common::{name, str_lit, ver};

#[test]
fn pep_701_version_gate() {
    assert!(supports_pep_701(&ver(3, 12)));
    assert!(!supports_pep_701(&ver(3, 11)));
}

#[test]
fn fstring_nested_format_spec() {
    let width: Expr = Expr::FormattedValue {
        value: Box::new(name("w")),
        conversion: FormatConversion::None,
        format_spec: None,
        line: None,
    };
    let spec: Expr = Expr::JoinedStr {
        values: vec![str_lit(">"), width],
        line: None,
    };
    let values: Vec<Expr> = vec![Expr::FormattedValue {
        value: Box::new(name("label")),
        conversion: FormatConversion::None,
        format_spec: Some(Box::new(spec)),
        line: None,
    }];
    let out: String = emit_fstring(&values, &ver(3, 12));
    assert_eq!(out, "f\"{label:>{w}}\"");
}
