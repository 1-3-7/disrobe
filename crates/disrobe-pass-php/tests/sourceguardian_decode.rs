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

use disrobe_pass_php::encoder::AuthorizationToken;
use disrobe_pass_php::{DecodeOutcome, sourceguardian_encoder};

#[test]
fn decode_requires_authorization() {
    let blob = common::build_sourceguardian_min();
    let err = sourceguardian_encoder::decode(&blob, None).expect_err("must require auth");
    assert!(format!("{err}").contains("DR-PHP-0070"));
}

#[test]
fn authorized_decode_returns_structural_for_version_comment() {
    let blob = common::build_sourceguardian_min();
    let outcome = sourceguardian_encoder::decode(&blob, Some(AuthorizationToken::user_attested()))
        .expect("decode");
    let DecodeOutcome::StructuralOnly { header, ciphertext } = outcome else {
        unreachable!("expected structural-only")
    };
    assert_eq!(header.version_label, "version-comment");
    assert!(!ciphertext.is_empty());
}

#[test]
fn unsupported_marker_variant_rejected() {
    let blob: &[u8] = b"<?php sg_load('payload');";
    let err = sourceguardian_encoder::decode(blob, Some(AuthorizationToken::user_attested()))
        .expect_err("unsupported");
    assert!(format!("{err}").contains("DR-PHP-0071"));
}
