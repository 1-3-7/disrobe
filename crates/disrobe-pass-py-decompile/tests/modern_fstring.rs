#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::literal_string_with_formatting_args
)]

mod common;

use disrobe_pass_py_decompile::ast::{Expr, FormatConversion};
use disrobe_pass_py_decompile::codegen::fstring_emit::emit_fstring;

use crate::common::{name, str_lit, ver};

#[test]
fn fstring_simple_literal_only() {
    let values: Vec<Expr> = vec![str_lit("hello")];
    let out: String = emit_fstring(&values, &ver(3, 6));
    assert_eq!(out, "f\"hello\"");
}

#[test]
fn fstring_with_simple_interpolation() {
    let values: Vec<Expr> = vec![
        str_lit("x="),
        Expr::FormattedValue {
            value: Box::new(name("x")),
            conversion: FormatConversion::None,
            format_spec: None,
            line: None,
        },
    ];
    let out: String = emit_fstring(&values, &ver(3, 8));
    assert_eq!(out, "f\"x={x}\"");
}

#[test]
fn fstring_with_repr_conversion() {
    let values: Vec<Expr> = vec![Expr::FormattedValue {
        value: Box::new(name("y")),
        conversion: FormatConversion::Repr,
        format_spec: None,
        line: None,
    }];
    let out: String = emit_fstring(&values, &ver(3, 10));
    assert_eq!(out, "f\"{y!r}\"");
}

#[test]
fn fstring_with_format_spec() {
    let spec: Expr = Expr::JoinedStr {
        values: vec![str_lit(".3f")],
        line: None,
    };
    let values: Vec<Expr> = vec![Expr::FormattedValue {
        value: Box::new(name("pi")),
        conversion: FormatConversion::None,
        format_spec: Some(Box::new(spec)),
        line: None,
    }];
    let out: String = emit_fstring(&values, &ver(3, 11));
    assert_eq!(out, "f\"{pi:.3f}\"");
}

#[test]
fn fstring_escapes_braces_in_literal() {
    let values: Vec<Expr> = vec![str_lit("{not interp}")];
    let out: String = emit_fstring(&values, &ver(3, 10));
    assert_eq!(out, "f\"{{not interp}}\"");
}
