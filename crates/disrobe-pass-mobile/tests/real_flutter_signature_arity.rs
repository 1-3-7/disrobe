#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{AotLiftReport, lift_libapp_aot};

const RECORDED_EXACT_AGREEMENT_FLOOR: usize = 30;

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("flutter")
}

fn read_sample(relative: &str) -> Vec<u8> {
    let mut path: PathBuf = corpus();
    for part in relative.split('/') {
        path = path.join(part);
    }
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("sample {} must be committed: {e}", path.display()))
}

#[test]
fn inferred_arity_never_claims_more_parameters_than_the_snapshot_declares() {
    let report: AotLiftReport =
        lift_libapp_aot(&read_sample("disrobe_sample/libapp_arm64.so")).expect("lift the sample");

    let mut compared: usize = 0;
    let mut exact: usize = 0;
    let mut overclaimed: Vec<String> = Vec::new();
    for function in &report.functions {
        let Some(declared): Option<u8> = function.declared_parameter_count else {
            continue;
        };
        let inferred: u8 = function.inferred_parameter_count;
        compared += 1;
        if inferred == declared {
            exact += 1;
        }
        if inferred > declared.saturating_add(1) {
            overclaimed.push(format!(
                "{} declared={declared} inferred={inferred}",
                function.name.as_deref().unwrap_or("<unnamed>")
            ));
        }
    }

    eprintln!(
        "arity inference against the snapshot's own declared parameter counts: {exact}/{compared} \
         exact, {} claiming more than declared plus receiver",
        overclaimed.len()
    );
    assert!(
        compared > 0,
        "the committed sample must declare parameter counts for this grade to read; without them \
         the inference has no reference"
    );
    assert!(
        overclaimed.len() <= 1,
        "arity inference claimed more parameters than the snapshot declares, allowing one register \
         for the receiver, on {} functions: {overclaimed:?}",
        overclaimed.len()
    );
    assert!(
        exact >= RECORDED_EXACT_AGREEMENT_FLOOR,
        "only {exact} of {compared} inferred arities match the declared count, below the recorded \
         floor of {RECORDED_EXACT_AGREEMENT_FLOOR}"
    );
}

#[test]
fn a_declared_parameter_count_overrides_the_inference_in_the_rendered_signature() {
    let report: AotLiftReport =
        lift_libapp_aot(&read_sample("disrobe_sample/libapp_arm64.so")).expect("lift the sample");
    let mut checked: usize = 0;
    for function in &report.functions {
        let Some(declared): Option<u8> = function.declared_parameter_count else {
            continue;
        };
        assert_eq!(
            function.arg_registers, declared,
            "a function whose parameter count the snapshot declares must render that count, not \
             the inference, in {:?}",
            function.name
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "the committed sample must carry declared parameter counts for this gate to mean anything"
    );
    eprintln!("functions rendering a declared parameter count: {checked}");
}

#[test]
fn an_inferred_arity_stays_within_the_dart_argument_register_file() {
    let mut checked: usize = 0;
    for sample in [
        "disrobe_sample/libapp_arm64.so",
        "pinned_graph_fixture/receipt_validator_arm64.so",
        "pinned_graph_fixture/receipt_validator_obfuscated_arm64.so",
        "pinned_graph_fixture/voucher_validator_arm64.so",
    ] {
        let report: AotLiftReport =
            lift_libapp_aot(&read_sample(sample)).expect("lift committed Dart sample");
        for function in &report.functions {
            assert!(
                function.inferred_parameter_count <= 6,
                "{sample} inferred {} parameters for {:?}; the Dart ARM64 convention passes at most \
                 six in registers, so a higher count means the inference is reading something that \
                 is not an argument register",
                function.inferred_parameter_count,
                function.name
            );
            checked += 1;
        }
    }
    eprintln!("functions whose inferred arity was range-checked: {checked}");
    assert!(checked > 0, "the corpus must lift functions");
}
