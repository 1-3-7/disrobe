#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use disrobe_pass_go::{GoAnalysis, analyze};

#[test]
fn goresym_normal_recovers_main_and_runtime() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_NORMAL) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze normal");
    assert!(analysis.symbols.funcs.len() > 100, "expected many funcs");
    let has_main: bool = analysis.symbols.funcs.iter().any(|f| f.name == "main.main");
    assert!(has_main, "missing main.main");
    let has_greet: bool = analysis
        .symbols
        .funcs
        .iter()
        .any(|f| f.name == "main.greet");
    assert!(has_greet, "missing main.greet");
    let has_runtime: bool = analysis
        .symbols
        .funcs
        .iter()
        .any(|f| f.name.starts_with("runtime."));
    assert!(has_runtime, "missing runtime.* funcs");
}

#[test]
fn goresym_buildversion_extracted() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_NORMAL) else {
        return;
    };
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze");
    let bv: &str = analysis.buildversion.as_deref().unwrap_or("");
    assert!(bv.starts_with("go1."), "buildversion not detected: {bv}");
}
