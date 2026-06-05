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
use disrobe_pass_php::{DecodeOutcome, ioncube_encoder};

#[test]
fn decode_without_authorization_is_rejected() {
    let blob = common::build_ioncube_v9_min();
    let err = ioncube_encoder::decode(&blob, None).expect_err("must require auth");
    assert!(format!("{err}").contains("DR-PHP-0060"));
}

#[test]
fn authorized_decode_emits_structural_only_for_v9() {
    let blob = common::build_ioncube_v9_min();
    let outcome =
        ioncube_encoder::decode(&blob, Some(AuthorizationToken::user_attested())).expect("decode");
    match outcome {
        DecodeOutcome::StructuralOnly { header, ciphertext } => {
            assert_eq!(header.version_label, "v9");
            assert!(!ciphertext.is_empty());
        }
        DecodeOutcome::PartialPlaintext { .. } => {
            unreachable!("expected structural-only for tiny fixture")
        }
    }
}

#[test]
fn unsupported_version_is_rejected_even_with_auth() {
    let mut blob: Vec<u8> = b"<?php //00A0".to_vec();
    blob.extend(std::iter::repeat_n(b'Z', 96));
    let err = ioncube_encoder::decode(&blob, Some(AuthorizationToken::user_attested()))
        .expect_err("unsupported");
    assert!(format!("{err}").contains("DR-PHP-0061"));
}
