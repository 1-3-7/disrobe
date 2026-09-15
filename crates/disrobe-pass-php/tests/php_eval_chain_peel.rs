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

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use disrobe_pass_php::{PeelLayer, PeelOptions, peel_eval_chain};
use flate2::Compression;
use flate2::write::DeflateEncoder;
use std::io::Write as _;

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
fn peels_arbitrary_order_nested_chain_rot13_interposed_between_b64_and_gz() {
    let original: &str = "$secret = 'triple-nested'; echo $secret;";
    let blob = common::build_rot13_interposed_chain(original);
    let report = peel_eval_chain(&blob, PeelOptions::default()).expect("peel");
    let recovered = String::from_utf8_lossy(&report.final_source);
    assert!(
        recovered.contains("triple-nested"),
        "gzinflate(str_rot13(base64_decode(...))) must resolve inside-out regardless of decode-fn order; got: {recovered}"
    );
    assert!(
        !report.residual_eval,
        "no residual eval should remain after full nested peel; got: {recovered}"
    );
    assert!(
        report.layer_counts.contains_key(&PeelLayer::GzInflate),
        "the outer gzinflate layer must be recorded; layers: {:?}",
        report.layer_counts.keys().collect::<Vec<_>>()
    );
}

#[test]
fn peels_base64_decode_wrapping_a_nested_strrev_call_in_the_eval_arg() {
    let original: &str = "echo 'strrev-inside-base64';";
    let blob = common::build_b64_wrapping_strrev_chain(original);
    let report = peel_eval_chain(&blob, PeelOptions::default()).expect("peel");
    let recovered = String::from_utf8_lossy(&report.final_source);
    assert!(
        recovered.contains("strrev-inside-base64"),
        "base64_decode(strrev('...')) in the eval arg must resolve the inner call, not stop at EvalUnwrap; got: {recovered}"
    );
    assert!(
        !report.residual_eval,
        "no residual eval should remain; got: {recovered}"
    );
}

#[test]
fn peels_base64_arg_built_from_concatenated_string_literals() {
    let original: &str = "echo 'split-literal-b64';";
    let blob = common::build_split_literal_b64_chain(original);
    let report = peel_eval_chain(&blob, PeelOptions::default()).expect("peel");
    let recovered = String::from_utf8_lossy(&report.final_source);
    assert!(
        recovered.contains("split-literal-b64"),
        "base64_decode('AAA'.'BBB') must join the literal-concat before decoding; got: {recovered}"
    );
    assert!(!report.residual_eval, "no residual eval; got: {recovered}");
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

#[test]
fn decompression_bomb_in_eval_chain_is_rejected_not_ooming() {
    let bomb_plain: Vec<u8> = vec![0u8; 300 * 1024 * 1024];
    let mut enc: DeflateEncoder<Vec<u8>> = DeflateEncoder::new(Vec::new(), Compression::best());
    enc.write_all(&bomb_plain).expect("deflate write");
    let deflated: Vec<u8> = enc.finish().expect("deflate finish");
    assert!(
        deflated.len() < 1024 * 1024,
        "300MB of zeros must deflate to a tiny stream, got {} bytes",
        deflated.len()
    );
    let encoded: String = B64.encode(&deflated);
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"<?php ev");
    blob.extend_from_slice(b"al(gzinflate(base64_decode('");
    blob.extend_from_slice(encoded.as_bytes());
    blob.extend_from_slice(b"')));");
    let err = peel_eval_chain(&blob, PeelOptions::default())
        .expect_err("inflate bomb must be capped, not OOM");
    assert!(
        format!("{err}").contains("DR-PHP-0035"),
        "expected GzInflateBomb cap, got: {err}"
    );
}

#[test]
fn malformed_gzinflate_payload_is_clean_err_no_panic() {
    let garbage: String = B64.encode(b"\xff\xfe\xfd\xfc not a valid deflate stream at all");
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"<?php ev");
    blob.extend_from_slice(b"al(gzinflate(base64_decode('");
    blob.extend_from_slice(garbage.as_bytes());
    blob.extend_from_slice(b"')));");
    let err = peel_eval_chain(&blob, PeelOptions::default())
        .expect_err("invalid deflate must error cleanly");
    assert!(
        format!("{err}").contains("DR-PHP-0034"),
        "expected GzInflateFailed, got: {err}"
    );
}

#[test]
fn depth_budget_caps_pathological_nesting() {
    let opts: PeelOptions = PeelOptions {
        max_depth: 4,
        stop_when_clean: true,
    };
    let original: &str = "echo 'deep';";
    let blob = common::build_eval_chain(original);
    let report = peel_eval_chain(&blob, opts).expect("shallow chain within budget");
    assert!(report.layers.len() <= 4);
}
