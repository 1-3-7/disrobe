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
fn peels_fopo_single_layer_to_inner_php() {
    let inner: &str = "echo 'fopo-inner';";
    let obfuscated = common::build_fopo(inner);
    let report = peel_eval_chain(&obfuscated, PeelOptions::default()).expect("peel");
    assert!(report.layer_counts.contains_key(&PeelLayer::Fopo));
    let recovered = String::from_utf8_lossy(&report.final_source);
    assert!(recovered.contains("fopo-inner"), "got: {recovered}");
}

#[test]
fn non_fopo_inline_base64_does_not_take_fopo_path() {
    let inner: &str = "echo 'inline-not-fopo';";
    let blob = common::build_b64_only_eval(inner);
    let report = peel_eval_chain(&blob, PeelOptions::default()).expect("peels via eval-chain");
    assert!(
        !report.layer_counts.contains_key(&PeelLayer::Fopo),
        "no FOPO marker present, so the FOPO peeler must not claim a layer"
    );
    assert!(report.layer_counts.contains_key(&PeelLayer::Base64Decode));
    let recovered = String::from_utf8_lossy(&report.final_source);
    assert!(recovered.contains("inline-not-fopo"), "got: {recovered}");
}

#[test]
fn variable_bound_base64_is_resolved_through_dataflow() {
    let loader: Vec<u8> = b"<?php $x='YWJjZA=='; eval(base64_decode($x));".to_vec();
    let report = peel_eval_chain(&loader, PeelOptions::default())
        .expect("two-statement loader binds the literal then resolves base64_decode($x)");
    assert!(
        report.layer_counts.contains_key(&PeelLayer::ModernLoader),
        "multi-statement variable binding is the modern-loader peeler's job"
    );
    let recovered = String::from_utf8_lossy(&report.final_source);
    assert_eq!(
        recovered, "abcd",
        "the literal bound to $x is traced into base64_decode and decoded"
    );
}
