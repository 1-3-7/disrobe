#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use disrobe_pass_go::{GoAnalysis, analyze};

#[test]
fn typemeta_emits_some_types_for_normal_binary() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_NORMAL) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze");
    let total_types: usize = analysis.typemeta.types.len();
    let total_itabs: usize = analysis.typemeta.itabs.len();
    let total: usize = total_types + total_itabs;
    assert!(
        total > 0 || analysis.moduledata.typelinks_va == 0,
        "expected typelinks/itablinks walk to find at least one entry"
    );
}

#[test]
fn typemeta_does_not_panic_on_stripped() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_STRIPPED) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze stripped");
    let _ = analysis.typemeta.types.len();
    let _ = analysis.typemeta.itabs.len();
}
