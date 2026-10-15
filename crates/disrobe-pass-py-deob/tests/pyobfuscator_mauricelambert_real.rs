#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::py_mauricelambert::PyObfuscatorMauricelambertPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, Obfuscator, PeelOutcome, Quality};

const OBF: &str = "pyobfuscator_mauricelambert";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Clean,
    Renamed,
    ToolOutputDoesNotParse,
}

const SLOTS: &[(&str, Expect)] = &[
    ("hello", Expect::Clean),
    ("edge_recursive", Expect::Renamed),
    ("edge_class_decorator", Expect::Renamed),
    ("edge_async_fn", Expect::Renamed),
    ("edge_generator", Expect::Renamed),
    ("edge_lambda_in_listcomp", Expect::Renamed),
    ("edge_walrus_operator", Expect::Renamed),
    ("edge_match_statement", Expect::ToolOutputDoesNotParse),
    ("edge_structural_pattern", Expect::ToolOutputDoesNotParse),
    ("edge_typing_generic", Expect::Renamed),
];

const GZIP_STAGES: [&str; 2] = ["bytes-literal-extract", "gzip-decompress"];
const FOLD_STAGES: [&str; 4] = [
    "bytes-literal-extract",
    "gzip-decompress",
    "builtin-alias-fold",
    "xor-string-fold",
];

fn parses(source: &str) -> bool {
    ruff_python_parser::parse_module(source).is_ok()
}

#[test]
fn mauricelambert_real_fixtures_fold_the_alias_table_and_string_decoder() {
    for (slot, expect) in SLOTS {
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
        let source: &str = &peel.recovered_source;
        match expect {
            Expect::ToolOutputDoesNotParse => {
                assert_eq!(peel.quality, Quality::Partial, "slot {slot}");
                assert_eq!(peel.stages_applied, GZIP_STAGES, "slot {slot}");
                assert!(
                    !parses(source),
                    "slot {slot}: the tool's own inner layer is not valid Python"
                );
                assert_eq!(
                    peel.diagnostics.get("inner_layer_len"),
                    Some(&source.len().to_string()),
                    "slot {slot}: the reported inner layer length must match the emitted layer"
                );
            }
            Expect::Clean | Expect::Renamed => {
                assert_eq!(peel.stages_applied, FOLD_STAGES, "slot {slot}");
                assert!(parses(source), "slot {slot}:\n{source}");
                assert!(
                    !source.contains("ArithmeticError")
                        && !source.contains("bytes([")
                        && !source.contains("getattr(")
                        && !source.contains("chr("),
                    "slot {slot}: the alias table, the XOR decoder, getattr lookups and chr \
                     arithmetic must all be folded:\n{source}"
                );
                let quality: Quality = if *expect == Expect::Clean {
                    Quality::Full
                } else {
                    Quality::Partial
                };
                assert_eq!(peel.quality, quality, "slot {slot}:\n{source}");
            }
        }
    }
}

#[test]
fn the_hello_capture_folds_to_its_one_call() {
    let fixture: Vec<u8> = common::require_real_fixture(OBF, "hello");
    let peel: PeelOutcome = PyObfuscatorMauricelambertPass
        .peel(&fixture)
        .expect("the hello capture peels");
    assert_eq!(peel.recovered_source, "print('hello world')\n");
}
