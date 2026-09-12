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

use disrobe_pass_php::{EncoderFamily, sourceguardian_encoder};

#[test]
fn detects_sourceguardian_version_comment() {
    let blob = common::build_sourceguardian_min();
    let detection = sourceguardian_encoder::detect(&blob).expect("detect");
    assert_eq!(detection.family, EncoderFamily::SourceGuardian);
    assert_eq!(detection.version_label, "version-comment");
}

#[test]
fn detects_sg_load_call() {
    let blob: &[u8] = b"<?php sg_load('something');";
    let detection = sourceguardian_encoder::detect(blob).expect("detect");
    assert_eq!(detection.version_label, "loader-call");
}

#[test]
fn returns_none_for_unrelated_php() {
    assert!(sourceguardian_encoder::detect(b"<?php echo 1;").is_none());
}
