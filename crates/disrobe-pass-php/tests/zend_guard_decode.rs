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
use disrobe_pass_php::{DecodeOutcome, zend_guard_encoder};

#[test]
fn decode_requires_authorization() {
    let blob = common::build_zend_guard_min();
    let err = zend_guard_encoder::decode(&blob, None).expect_err("must require auth");
    assert!(format!("{err}").contains("DR-PHP-0080"));
}

#[test]
fn authorized_decode_strips_static_xor_layer_for_zend3() {
    let blob = common::build_zend_guard_min();
    let outcome = zend_guard_encoder::decode(&blob, Some(AuthorizationToken::user_attested()))
        .expect("decode");
    let DecodeOutcome::PartialPlaintext {
        header, recovered, ..
    } = outcome
    else {
        unreachable!("expected partial-plaintext after static xor strip")
    };
    assert_eq!(header.version_label, "zend-3");
    assert_eq!(recovered, common::ZEND_GUARD_MIN_PLAINTEXT);
}

#[test]
fn unsupported_banner_rejected() {
    let blob: &[u8] = b"<?php /* Zend Optimizer */";
    let err = zend_guard_encoder::decode(blob, Some(AuthorizationToken::user_attested()))
        .expect_err("unsupported");
    assert!(format!("{err}").contains("DR-PHP-0081"));
}
