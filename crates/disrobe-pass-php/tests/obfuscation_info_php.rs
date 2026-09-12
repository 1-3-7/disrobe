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
fn detects_obfuscation_info_wrap_markers() {
    let blob = common::build_obfuscation_info();
    let report = signature_scan(&blob);
    let count: u32 = report
        .families
        .get(&SignatureFamily::ObfuscationInfo)
        .copied()
        .unwrap_or(0);
    assert!(count >= 2, "expected >=2 ObfuscationInfo hits, got {count}");
}

#[test]
fn vendor_url_alone_is_sufficient() {
    let blob: &[u8] = b"<?php /* obfuscation.info served */";
    let report = signature_scan(blob);
    assert!(
        report
            .families
            .get(&SignatureFamily::ObfuscationInfo)
            .copied()
            .unwrap_or(0)
            >= 1
    );
}
