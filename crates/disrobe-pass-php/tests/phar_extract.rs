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

use disrobe_pass_php::{extract_phar_entry, parse_phar};

#[test]
fn parses_tiny_phar_with_one_file() {
    let phar = common::build_tiny_phar(
        &common::default_phar_stub(),
        &[("hello.php", b"<?php echo 'hi';")],
    );
    let archive = parse_phar(&phar).expect("parse");
    assert_eq!(archive.entries.len(), 1);
    let entry = archive.entries.get("hello.php").expect("entry");
    assert_eq!(entry.uncompressed_size, 16);
    assert_eq!(entry.stored_size, 16);
}

#[test]
fn extracts_uncompressed_payload_byte_perfect() {
    let body: &[u8] = b"<?php return 42;";
    let phar = common::build_tiny_phar(&common::default_phar_stub(), &[("r.php", body)]);
    let archive = parse_phar(&phar).expect("parse");
    let extracted = extract_phar_entry(&archive, &phar, "r.php").expect("extract");
    assert_eq!(extracted, body);
}

#[test]
fn parses_multi_entry_phar_sorted_btree() {
    let phar = common::build_tiny_phar(
        &common::default_phar_stub(),
        &[
            ("zeta.php", b"<?php //z"),
            ("alpha.php", b"<?php //a"),
            ("mu.php", b"<?php //m"),
        ],
    );
    let archive = parse_phar(&phar).expect("parse");
    let names: Vec<&str> = archive.entries.keys().map(String::as_str).collect();
    assert_eq!(names, ["alpha.php", "mu.php", "zeta.php"]);
}

#[test]
fn rejects_phar_without_halt_sentinel() {
    let err = parse_phar(b"<?php echo 1;").expect_err("must fail");
    let msg = format!("{err}");
    assert!(msg.contains("DR-PHP-0021"), "got: {msg}");
}

#[test]
fn rejects_too_small_input() {
    let err = parse_phar(b"ab").expect_err("must fail");
    let msg = format!("{err}");
    assert!(msg.contains("DR-PHP-0020"), "got: {msg}");
}
