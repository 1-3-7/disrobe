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
fn detects_smuggler_markers() {
    let blob = common::build_smuggler();
    let report = signature_scan(&blob);
    let count: u32 = report
        .families
        .get(&SignatureFamily::Smuggler)
        .copied()
        .unwrap_or(0);
    assert!(count >= 2, "expected >=2 smuggler hits, got {count}");
}
