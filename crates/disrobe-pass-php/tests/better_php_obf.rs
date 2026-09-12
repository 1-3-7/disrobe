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

use disrobe_pass_php::{PeelLayer, PeelOptions, peel_eval_chain};

#[test]
fn peels_better_php_obfuscator_signature_layer() {
    let original: &str = "echo 'better-recovered';";
    let blob = common::build_better_php_obf(original);
    let report = peel_eval_chain(&blob, PeelOptions::default()).expect("peel");
    assert!(
        report
            .layer_counts
            .contains_key(&PeelLayer::BetterPhpObfuscator)
    );
    let recovered = String::from_utf8_lossy(&report.final_source);
    assert!(recovered.contains("better-recovered"), "got: {recovered}");
}
