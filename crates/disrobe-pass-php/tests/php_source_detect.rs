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

use disrobe_pass_php::{PhpConfidence, PhpKind, detect_php};

#[test]
fn detects_full_open_tag_as_definite_source() {
    let detection = detect_php(b"<?php echo 1;");
    assert_eq!(detection.kind, PhpKind::Source);
    assert_eq!(detection.confidence, PhpConfidence::Definite);
    assert_eq!(detection.open_tag_offset, Some(0));
}

#[test]
fn detects_short_open_tag_with_echo_marker() {
    let detection = detect_php(b"<?= $x ?>");
    assert_eq!(detection.kind, PhpKind::Source);
    assert_eq!(detection.confidence, PhpConfidence::Medium);
}

#[test]
fn rejects_unrelated_bytes_as_unknown() {
    let detection = detect_php(b"random binary \x00\x01");
    assert_eq!(detection.kind, PhpKind::Unknown);
}

#[test]
fn detects_phar_archive_when_halt_and_signature_present() {
    let phar = common::build_tiny_phar(&common::default_phar_stub(), &[("a.php", b"<?php 1;")]);
    let detection = detect_php(&phar);
    assert_eq!(detection.kind, PhpKind::PharArchive);
    assert!(detection.has_halt_compiler);
}

#[test]
fn detects_bare_phar_stub_when_only_halt() {
    let detection = detect_php(b"<?php __HALT_COMPILER(); ?>");
    assert_eq!(detection.kind, PhpKind::PharStub);
}
