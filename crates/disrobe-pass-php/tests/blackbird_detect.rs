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

use disrobe_pass_php::{SignatureFamily, signature_scan};

#[test]
fn detects_blackbird_global_handle_and_loader() {
    let blob = common::build_blackbird();
    let report = signature_scan(&blob);
    let count: u32 = report
        .families
        .get(&SignatureFamily::Blackbird)
        .copied()
        .unwrap_or(0);
    assert!(count >= 2, "expected >=2 blackbird hits, got {count}");
}

#[test]
fn clean_php_yields_no_blackbird_hits() {
    let report = signature_scan(b"<?php echo 'hello';");
    assert!(!report.families.contains_key(&SignatureFamily::Blackbird));
}
