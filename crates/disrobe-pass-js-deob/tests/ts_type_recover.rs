#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{DtsCorpus, TypeRecoveryResult, recover_typescript};

#[test]
fn recovers_primitive_types_from_minified_js() {
    let src: &str = "var a = 'hello'; var b = 42; var c = true; var d = null;";
    let res: TypeRecoveryResult = recover_typescript(src, &DtsCorpus::well_known());
    assert!(res.stats.annotations_emitted >= 4, "{:?}", res.stats);
    assert!(res.emitted_ts.contains("declare const a:"));
    assert!(res.emitted_ts.contains("declare const b:"));
    assert!(res.emitted_ts.contains("declare const c:"));
    assert!(res.emitted_ts.contains("declare const d:"));
}

#[test]
fn corpus_match_wins_over_flow_inference() {
    let src: &str = "var useState = function(s){return [s, function(){}];};";
    let res: TypeRecoveryResult = recover_typescript(src, &DtsCorpus::well_known());
    assert_eq!(res.stats.symbols_matched_via_corpus, 1, "{:?}", res.stats);
    let sig: &String = res.annotations.get("useState").expect("got useState");
    assert!(sig.contains("=>"), "expected corpus signature, got {sig}");
}

#[test]
fn object_literal_shape_recovered() {
    let src: &str = "var config = { host: 'x', port: 1, ssl: true };";
    let res: TypeRecoveryResult = recover_typescript(src, &DtsCorpus::new());
    let sig: &String = res.annotations.get("config").expect("got config");
    assert!(sig.contains("host"), "missing host in {sig}");
    assert!(sig.contains("port"), "missing port in {sig}");
}

#[test]
fn arithmetic_yields_number_primitive() {
    let src: &str = "var total = 1 + 2 * 3;";
    let res: TypeRecoveryResult = recover_typescript(src, &DtsCorpus::new());
    let sig: &String = res.annotations.get("total").expect("got total");
    assert!(sig.contains("number"), "expected 'number', got {sig}");
}
