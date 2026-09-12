#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    unreachable_pub,
    dead_code,
    clippy::print_stdout,
    clippy::redundant_pub_crate,
    clippy::std_instead_of_alloc,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]

mod common;

use disrobe_pass_php::{TokKind, tokenize};

#[test]
fn tokenizes_basic_open_tag_and_variable() {
    let toks = tokenize(b"<?php $foo = 1;").expect("tokenize");
    assert!(toks.iter().any(|t| matches!(t.kind, TokKind::OpenTag)));
    assert!(
        toks.iter()
            .any(|t| matches!(t.kind, TokKind::Variable) && t.lexeme == b"$foo")
    );
    assert!(
        toks.iter()
            .any(|t| matches!(t.kind, TokKind::LongNumber) && t.lexeme == b"1")
    );
}

#[test]
fn tokenizes_double_quoted_and_heredoc_strings() {
    let src: &[u8] = b"<?php $s = \"hi $name\"; $h = <<<EOT\nbody\nEOT;\n";
    let toks = tokenize(src).expect("tokenize");
    assert!(toks.iter().any(|t| matches!(t.kind, TokKind::StringDouble)));
    assert!(toks.iter().any(|t| matches!(t.kind, TokKind::Heredoc)));
}

#[test]
fn handles_php8_arrow_and_nullsafe_punct() {
    let src: &[u8] = b"<?php $a = $obj?->m; $b = ['k' => 1]; $c = $obj->p; $d = Foo::BAR;";
    let toks = tokenize(src).expect("tokenize");
    assert!(toks.iter().any(|t| matches!(t.kind, TokKind::NullsafeOp)));
    assert!(toks.iter().any(|t| matches!(t.kind, TokKind::ObjectOp)));
    assert!(toks.iter().any(|t| matches!(t.kind, TokKind::DoubleArrow)));
    assert!(toks.iter().any(|t| matches!(t.kind, TokKind::ScopeRes)));
}

#[test]
fn tokenizes_comments_and_doc_comments() {
    let src: &[u8] = b"<?php /** doc */ /* block */ // line\n# also\n$x=1;";
    let toks = tokenize(src).expect("tokenize");
    assert!(toks.iter().any(|t| matches!(t.kind, TokKind::DocComment)));
    assert!(toks.iter().any(|t| matches!(t.kind, TokKind::BlockComment)));
    let line_count: usize = toks
        .iter()
        .filter(|t| matches!(t.kind, TokKind::LineComment))
        .count();
    assert_eq!(line_count, 2);
}

#[test]
fn handles_inline_html_and_close_tag() {
    let src: &[u8] = b"<html><?php echo 1; ?> tail";
    let toks = tokenize(src).expect("tokenize");
    assert!(
        toks.iter()
            .any(|t| matches!(t.kind, TokKind::InlineHtml) && t.lexeme == b"<html>")
    );
    assert!(toks.iter().any(|t| matches!(t.kind, TokKind::CloseTag)));
    assert!(
        toks.iter()
            .any(|t| matches!(t.kind, TokKind::InlineHtml) && t.lexeme.ends_with(b"tail"))
    );
}
