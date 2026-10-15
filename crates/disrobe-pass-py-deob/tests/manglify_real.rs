#![allow(clippy::expect_used, clippy::panic)]
mod common;

use std::time::Duration;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::manglify::ManglifyPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};
use ruff_python_parser::parse_module;

const SLOTS: &[&str] = &[
    "edge_cases_3_8",
    "edge_hello_world",
    "edge_async_fn",
    "edge_lambda_in_listcomp",
    "edge_typing_generic",
    "edge_walrus_operator",
];

const KEY_RANGE: std::ops::Range<u64> = 1000..9999;

#[test]
fn no_cpython_builtin_name_carries_a_digit() {
    for python in [common::require_python_314(), common::require_python_312()] {
        let output: ToolOutput = tool_output(
            CommandSpec::new(&python, Duration::from_mins(1))
                .arg("-I")
                .arg("-c")
                .arg("import builtins; print(' '.join(dir(builtins)))"),
        )
        .unwrap_or_else(|e| panic!("{} did not list its builtins: {e}", python.display()));
        let names: String = output.stdout_text();
        assert!(
            names.contains("print") && names.contains("ValueError"),
            "{names}"
        );
        let digits: Vec<&str> = names
            .split_whitespace()
            .filter(|name: &&str| name.bytes().any(|byte: u8| byte.is_ascii_digit()))
            .collect();
        assert!(
            digits.is_empty(),
            "the Engine decoy proof treats a name with a digit as unbound, but {} defines {digits:?}",
            python.display()
        );
    }
}

#[test]
fn manglify_real_fixtures_detect_and_peel() {
    for slot in SLOTS {
        let fixture: Vec<u8> = common::require_real_fixture("manglify", slot);
        let original: String = String::from_utf8_lossy(&fixture).into_owned();
        assert!(
            original.contains("class Engine") && original.contains("def Combustion"),
            "manglify slot {slot}: the upstream fixture must carry the Engine loader"
        );
        let det: DetectReport = ManglifyPass.detect(&fixture);
        assert!(det.matched, "manglify slot {slot} not detected: {det:?}");
        let peel: PeelOutcome = ManglifyPass
            .peel(&fixture)
            .unwrap_or_else(|e| panic!("manglify slot {slot} peel: {e:?}"));
        assert_eq!(
            peel.quality,
            Quality::Full,
            "manglify slot {slot}: the Engine key search must unlock the payload; diagnostics={:?}",
            peel.diagnostics
        );
        let key: u64 = peel
            .diagnostics
            .get("engine_keys")
            .and_then(|keys: &String| keys.parse::<u64>().ok())
            .unwrap_or_else(|| panic!("manglify slot {slot}: one key per layer: {peel:?}"));
        assert!(
            KEY_RANGE.contains(&key),
            "manglify slot {slot}: key {key} lies outside the loader's Intake range"
        );
        let source: &str = &peel.recovered_source;
        assert!(
            !source.contains("class Engine")
                && !source.contains("globals().get(")
                && !source.starts_with("pass;"),
            "manglify slot {slot}: the loader, its integrity check and its pass prefix must be gone:\n{source}"
        );
        assert!(
            parse_module(source).is_ok(),
            "manglify slot {slot}: the payload must parse:\n{source}"
        );
    }
}
