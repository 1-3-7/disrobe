#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{
    IntegrityStripStats, JscramblerDetection, JscramblerTier, detect_free_tier,
    strip_integrity_loops,
};

const SAMPLE: &str = include_str!("../../../corpus/src/javascript/jscrambler-free-sample.js");

#[test]
fn jscrambler_sample_detects_as_free_tier() {
    let det: JscramblerDetection = detect_free_tier(SAMPLE);
    assert!(det.matched, "expected Jscrambler match: {det:?}");
    assert_eq!(det.tier, JscramblerTier::Free);
    assert!(det.a0_hex_ident_count >= 5);
    assert!(det.integrity_loop_count >= 1);
}

#[test]
fn jscrambler_integrity_iife_stripped_to_empty() {
    let (out, stats): (String, IntegrityStripStats) = strip_integrity_loops(SAMPLE);
    assert!(
        stats.iifes_stripped >= 1 || stats.bare_loops_stripped >= 1,
        "no integrity construct stripped: stats={stats:?} out={out}"
    );
    assert!(out.contains("console.log"));
    assert!(stats.bytes_removed > 0);
}
