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
fn variable_indirection_unwraps_eval_but_cannot_resolve_base64() {
    let no_marker: Vec<u8> = b"<?php $x='YWJjZA=='; eval(base64_decode($x));".to_vec();
    let report = peel_eval_chain(&no_marker, PeelOptions::default())
        .expect("eval wrapper is unwrapped even when the argument is an unresolved variable");
    assert!(
        report.layer_counts.contains_key(&PeelLayer::EvalUnwrap),
        "eval() wrapper peeled to expose the inner call"
    );
    assert!(
        !report.layer_counts.contains_key(&PeelLayer::Base64Decode),
        "base64_decode($x) is a variable arg, NOT a static string, so it must not be decoded"
    );
    let recovered = String::from_utf8_lossy(&report.final_source);
    assert_eq!(
        recovered, "base64_decode($x)",
        "exposes the unresolved indirection literally, no fake decode"
    );
}
