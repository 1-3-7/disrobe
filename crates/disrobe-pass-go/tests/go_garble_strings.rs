#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use disrobe_pass_go::{GoAnalysis, analyze};

#[test]
fn garble_strings_include_embed_marker() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_NORMAL) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze normal");
    assert!(
        !analysis.garble.recovered_strings.is_empty(),
        "expected at least one recovered string from the rodata sections"
    );
    let any_marker_or_runtime: bool = analysis
        .garble
        .recovered_strings
        .iter()
        .any(|s| s.contains("disrobe-embed-payload-marker") || s.contains("runtime."));
    assert!(
        any_marker_or_runtime,
        "expected to recover either the embed marker or a runtime.* string fragment"
    );
}

#[test]
fn garble_strings_runs_on_garble_binary_without_panic() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_GARBLE) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze garbled");
    let _ = analysis.garble.recovered_strings.len();
}
