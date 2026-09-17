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

use disrobe_pass_php::{BcgKind, read_bcg_header};

#[test]
fn reads_tiny_bcg_header() {
    let blob = common::build_tiny_bcg();
    let header = read_bcg_header(&blob).expect("header");
    assert_eq!(header.kind, BcgKind::Bcg);
    assert_eq!(header.php_major, Some(8));
    assert_eq!(header.class_count, Some(1));
    assert_eq!(header.function_count, Some(2));
}

#[test]
fn rejects_too_small_bcg() {
    let err = read_bcg_header(b"BCG\x00").expect_err("too small");
    assert!(format!("{err}").contains("DR-PHP-0040"));
}

#[test]
fn rejects_bad_magic() {
    let bytes: Vec<u8> = vec![b'X', b'Y', b'Z', 0u8, 8, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0];
    let err = read_bcg_header(&bytes).expect_err("bad magic");
    assert!(format!("{err}").contains("DR-PHP-0041"));
}
