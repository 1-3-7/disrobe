#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::py_mauricelambert::PyObfuscatorMauricelambertPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, Obfuscator, PeelOutcome, Quality};

const OBF: &str = "pyobfuscator_mauricelambert";

const SLOTS: &[(&str, bool)] = &[
    ("hello", true),
    ("edge_recursive", true),
    ("edge_class_decorator", true),
    ("edge_async_fn", true),
    ("edge_generator", true),
    ("edge_lambda_in_listcomp", true),
    ("edge_walrus_operator", true),
    ("edge_match_statement", false),
    ("edge_structural_pattern", true),
    ("edge_typing_generic", true),
];

#[test]
fn mauricelambert_real_fixtures_peel_gzip_layer() {
    for (slot, inner_layer_parses) in SLOTS {
        let fixture: Vec<u8> = common::require_real_fixture(OBF, slot);
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
        assert_eq!(
            peel.stages_applied,
            vec![
                "bytes-literal-extract".to_owned(),
                "gzip-decompress".to_owned()
            ],
            "mauricelambert slot {slot}: expected exactly the bytes-literal and gzip stages"
        );
        assert_eq!(
            peel.diagnostics.get("inner_layer_len"),
            Some(&peel.recovered_source.len().to_string()),
            "mauricelambert slot {slot}: the reported inner layer length must match the emitted layer"
        );
        assert!(
            peel.recovered_source.len() > 200,
            "mauricelambert slot {slot}: gzip-decompressed inner layer should be substantial, got {} bytes",
            peel.recovered_source.len()
        );
        if *inner_layer_parses {
            assert!(
                ruff_python_parser::parse(
                    &peel.recovered_source,
                    ruff_python_parser::ParseOptions::from(ruff_python_parser::Mode::Module)
                )
                .is_ok(),
                "mauricelambert slot {slot}: the decompressed inner layer must parse as Python; \
                 first 200: {:?}",
                peel.recovered_source.chars().take(200).collect::<String>()
            );
        }
    }
}
