#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::py_mauricelambert::PyObfuscatorMauricelambertPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, Obfuscator, PeelOutcome, Quality};

const OBF: &str = "pyobfuscator_mauricelambert";

const SLOTS: &[&str] = &[
    "hello",
    "edge_recursive",
    "edge_class_decorator",
    "edge_async_fn",
    "edge_generator",
    "edge_lambda_in_listcomp",
    "edge_walrus_operator",
    "edge_match_statement",
    "edge_structural_pattern",
    "edge_typing_generic",
];

/// Recovers the gzip layer of `PyObfuscator` (`Mauricelambert`) artifacts as `Quality::Partial`.
#[test]
fn mauricelambert_real_fixtures_peel_gzip_layer() {
    let mut tested: usize = 0;
    for slot in SLOTS {
        let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, slot) else {
            continue;
        };
        tested += 1;
        let detect: DetectReport = PyObfuscatorMauricelambertPass.detect(&fixture);
        assert_eq!(detect.obfuscator, Obfuscator::PyObfuscatorMauricelambert);
        assert!(
            detect.matched,
            "mauricelambert slot {slot} not detected: {detect:?}"
        );
        let peel: PeelOutcome = PyObfuscatorMauricelambertPass
            .peel(&fixture)
            .unwrap_or_else(|e| panic!("mauricelambert slot {slot} peel: {e:?}"));
        assert_eq!(
            peel.quality,
            Quality::Partial,
            "mauricelambert slot {slot}: gzip layer-peel is an honest Partial, got {:?}",
            peel.quality
        );
        assert!(
            peel.stages_applied
                .iter()
                .any(|s: &String| s == "gzip-decompress"),
            "mauricelambert slot {slot}: expected gzip-decompress stage, got {:?}",
            peel.stages_applied
        );
        assert!(
            peel.recovered_source.len() > 200,
            "mauricelambert slot {slot}: gzip-decompressed inner layer should be substantial, got {} bytes",
            peel.recovered_source.len()
        );
    }
    if tested == 0 {
        common::skip_absent_corpus("mauricelambert_real_fixtures_peel_gzip_layer", OBF);
        return;
    }
    assert!(
        tested >= 9,
        "expected 9+ mauricelambert real fixtures, got {tested}"
    );
}
