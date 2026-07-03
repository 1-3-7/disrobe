#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use disrobe_pass_py_decompile::ast::{FormatConversion, TStrItem};
use disrobe_pass_py_decompile::codegen::tstring_emit::{emit_tstring, supports_tstring};

use crate::common::{name, ver};

#[test]
fn tstring_version_gate() {
    assert!(supports_tstring(&ver(3, 14)));
    assert!(!supports_tstring(&ver(3, 13)));
}

#[test]
fn tstring_literal_only() {
    let items: Vec<TStrItem> = vec![TStrItem::Literal("plain".to_owned())];
    let out: String = emit_tstring(&items, &ver(3, 14));
    assert_eq!(out, "t\"plain\"");
}

#[test]
fn tstring_with_interpolation() {
    let items: Vec<TStrItem> = vec![
        TStrItem::Literal("hello ".to_owned()),
        TStrItem::Interp {
            value: name("name"),
            expr_text: None,
            conversion: FormatConversion::None,
            format_spec: None,
        },
        TStrItem::Literal("!".to_owned()),
    ];
    let out: String = emit_tstring(&items, &ver(3, 14));
    assert_eq!(out, "t\"hello {name}!\"");
}

#[test]
fn tstring_falls_back_to_fstring_on_older_version() {
    let items: Vec<TStrItem> = vec![TStrItem::Literal("x".to_owned())];
    let out: String = emit_tstring(&items, &ver(3, 12));
    assert_eq!(out, "f\"x\"");
}
