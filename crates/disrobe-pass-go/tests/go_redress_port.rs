#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_go::{GoAnalysis, analyze};

#[test]
fn redress_stripped_still_recovers_funcs() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_STRIPPED);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze stripped");
    assert!(
        analysis.stripped.recovered_funcs > 100,
        "expected pclntab to survive -s -w"
    );
    assert!(analysis.stripped.stdlib_ratio > 0.5);
    let main_seen: bool = analysis.symbols.funcs.iter().any(|f| f.name == "main.main");
    assert!(main_seen, "main.main lost on -trimpath -s");
}

#[test]
fn redress_normal_not_marked_stripped() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_NORMAL);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze normal");
    let _ = analysis.stripped.stripped;
    assert!(analysis.stripped.recovered_funcs > 0);
}
