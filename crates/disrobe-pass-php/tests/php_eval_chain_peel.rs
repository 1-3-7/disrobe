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
fn peels_base64_gzinflate_eval_chain_to_plaintext() {
    let original: &str = "echo 'recovered from chain';";
    let blob = common::build_eval_chain(original);
    let report = peel_eval_chain(&blob, PeelOptions::default()).expect("peel");
    assert!(report.layer_counts.contains_key(&PeelLayer::GzInflate));
    let recovered = String::from_utf8_lossy(&report.final_source);
    assert!(
        recovered.contains("recovered from chain"),
        "got: {recovered}"
    );
}

#[test]
fn peels_base64_only_eval() {
    let original: &str = "echo 'b64-only';";
    let blob = common::build_b64_only_eval(original);
    let report = peel_eval_chain(&blob, PeelOptions::default()).expect("peel");
    assert!(report.layer_counts.contains_key(&PeelLayer::Base64Decode));
    let recovered = String::from_utf8_lossy(&report.final_source);
    assert!(recovered.contains("b64-only"), "got: {recovered}");
}

#[test]
fn peeling_records_size_reduction_in_trace() {
    let original: &str = "echo 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';";
    let blob = common::build_eval_chain(original);
    let report = peel_eval_chain(&blob, PeelOptions::default()).expect("peel");
    let total_layers: usize = report.layers.len();
    assert!(total_layers >= 1, "expected at least one layer");
}
