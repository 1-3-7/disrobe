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
fn flags_post_eval_and_request_shell_exec_as_webshell() {
    let blob = common::build_webshell();
    let report = signature_scan(&blob);
    let count: u32 = report
        .families
        .get(&SignatureFamily::WebShell)
        .copied()
        .unwrap_or(0);
    assert!(count >= 2, "expected >=2 webshell hits, got {count}");
}

#[test]
fn flags_known_named_shells_individually() {
    let blob = common::build_named_shell_samples();
    let report = signature_scan(&blob);
    let count: u32 = report
        .families
        .get(&SignatureFamily::WebShell)
        .copied()
        .unwrap_or(0);
    assert!(count >= 4, "expected >=4 named-shell hits, got {count}");
}
