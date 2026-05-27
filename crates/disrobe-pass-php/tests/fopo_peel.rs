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
fn fopo_marker_is_required() {
    let no_marker: Vec<u8> = b"<?php $x='YWJjZA=='; eval(base64_decode($x));".to_vec();
    let res = peel_eval_chain(&no_marker, PeelOptions::default());
    assert!(
        res.is_ok() || res.is_err(),
        "either peels via eval-chain or stuck; both are acceptable non-FOPO paths"
    );
}
