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

use disrobe_pass_php::{EncoderFamily, ioncube_encoder};

#[test]
fn detects_ioncube_v9_marker() {
    let blob = common::build_ioncube_v9_min();
    let detection = ioncube_encoder::detect(&blob).expect("detect");
    assert_eq!(detection.family, EncoderFamily::IonCube);
    assert_eq!(detection.version_label, "v9");
    assert!(detection.confident);
}

#[test]
fn returns_none_for_clean_php() {
    assert!(ioncube_encoder::detect(b"<?php echo 1;").is_none());
}

#[test]
fn detects_ioncube_loader_call_low_confidence() {
    let blob: &[u8] = b"<?php ioncube_loader('payload');";
    let detection = ioncube_encoder::detect(blob).expect("detect");
    assert_eq!(detection.family, EncoderFamily::IonCube);
    assert_eq!(detection.version_label, "unknown");
    assert!(!detection.confident);
}
