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
fn peels_str_rot13_eval() {
    let original: &str = "echo 'rot13-recovered';";
    let blob = common::build_str_rot13(original);
    let report = peel_eval_chain(&blob, PeelOptions::default()).expect("peel");
    assert!(report.layer_counts.contains_key(&PeelLayer::StrRot13));
    let recovered = String::from_utf8_lossy(&report.final_source);
    assert!(recovered.contains("rot13-recovered"), "got: {recovered}");
}

#[test]
fn peels_str_replace_indirection() {
    let original: &str = "return sr_recovered;";
    let blob = common::build_str_replace(original, "XX", "re");
    let report = peel_eval_chain(&blob, PeelOptions::default()).expect("peel");
    assert!(report.layer_counts.contains_key(&PeelLayer::StrReplace));
    let recovered = String::from_utf8_lossy(&report.final_source);
    assert!(recovered.contains("sr_recovered"), "got: {recovered}");
}
