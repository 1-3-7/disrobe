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

use disrobe_pass_php::{EncoderFamily, zend_guard_encoder};

#[test]
fn detects_zend_guard_3_marker() {
    let blob = common::build_zend_guard_min();
    let detection = zend_guard_encoder::detect(&blob).expect("detect");
    assert_eq!(detection.family, EncoderFamily::ZendGuard);
    assert_eq!(detection.version_label, "zend-3");
}

#[test]
fn detects_zend_guard_loader_banner() {
    let blob: &[u8] = b"<?php /* Zend Guard Loader v6 */";
    let detection = zend_guard_encoder::detect(blob).expect("detect");
    assert_eq!(detection.version_label, "guard-loader-banner");
}

#[test]
fn returns_none_for_unrelated_php() {
    assert!(zend_guard_encoder::detect(b"<?php echo 1;").is_none());
}
