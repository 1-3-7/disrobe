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

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use disrobe_pass_php::encoder::AuthorizationToken;
use disrobe_pass_php::{DecodeOutcome, sourceguardian_encoder};

const HELLO_DZOA: &[u8] = include_bytes!("fixtures/protector_oparray/hello.dzoa");

#[test]
fn decode_requires_authorization() {
    let blob = common::build_sourceguardian_min();
    let err = sourceguardian_encoder::decode(&blob, None).expect_err("must require auth");
    assert!(format!("{err}").contains("DR-PHP-0070"));
}

#[test]
fn decode_without_authorization_recovers_static_raw_oparray_body() {
    let mut blob: Vec<u8> = b"<?php sg_load('".to_vec();
    blob.extend_from_slice(B64.encode(HELLO_DZOA).as_bytes());
    blob.extend_from_slice(b"');");
    let outcome: DecodeOutcome =
        sourceguardian_encoder::decode(&blob, None).expect("static body decode");
    let DecodeOutcome::PartialPlaintext { recovered, .. } = outcome else {
        unreachable!("expected static body recovery")
    };
    assert_eq!(recovered, HELLO_DZOA);
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
fn sg_load_without_valid_container_walls_to_structural_only() {
    let mut blob: Vec<u8> = b"<?php sg_load('not-a-real-container-argument');".to_vec();
    blob.extend(std::iter::repeat_n(b'Z', 96));
    let outcome = sourceguardian_encoder::decode(&blob, Some(AuthorizationToken::user_attested()))
        .expect("detected sg_load is routed, not error");
    let DecodeOutcome::StructuralOnly { header, ciphertext } = outcome else {
        unreachable!("sg_load arg is not a valid container, so the opcode body is walled")
    };
    assert_eq!(header.version_label, "loader-call");
    assert!(
        !ciphertext.is_empty(),
        "structural ciphertext boundary reported, no fabricated source"
    );
}
