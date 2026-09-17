#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{
    DecompileReport, DecompiledFunction, HermesModule, decompile_hermes_module, parse_hermes_module,
};

const PUBLISHED_HEADING: &str = "React Native Hermes (committed hermesc-built HBC v96 sample";
const PUBLISHED_BAR: &str = "op-coverage";

fn published_bar(heading_needle: &str, label: &str) -> serde_json::Value {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("xtask")
        .join("data")
        .join("recovery.json");
    let raw: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e: serde_json::Error| panic!("parse {}: {e}", path.display()));
    let mut found: Vec<serde_json::Value> = Vec::new();
    for group in doc["groups"].as_array().expect("groups array") {
        let heading_matches: bool = group["heading"]
            .as_str()
            .is_some_and(|h: &str| h.contains(heading_needle));
        if !heading_matches {
            continue;
        }
        for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
            if bar["label"].as_str() == Some(label) {
                found.push(bar.clone());
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "xtask/data/recovery.json must carry exactly one bar labelled `{label}` under a heading \
         containing `{heading_needle}`, found {}",
        found.len()
    );
    found.remove(0)
}

fn sample(file: &str) -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("hermes")
        .join("sample")
        .join(file)
}

fn function<'a>(report: &'a DecompileReport, name: &str) -> &'a DecompiledFunction {
    report
        .functions
        .iter()
        .find(|f: &&DecompiledFunction| f.name == name)
        .unwrap_or_else(|| panic!("function {name} not recovered"))
}

#[test]
fn hbc_v96_sample_recovers_every_function_at_full_op_coverage() {
    let bytes: Vec<u8> = std::fs::read(sample("sample.hbc.v96")).expect("read v96 sample");
    assert_eq!(
        &bytes[8..12],
        &96u32.to_le_bytes(),
        "committed fixture must be HBC bytecode version 96"
    );

    let module: HermesModule = parse_hermes_module(&bytes).expect("parse v96 module");
    let report: DecompileReport = decompile_hermes_module(&module);
    assert_eq!(report.hermes_version, 96);

    let total_ops: usize = report.total_reconstructed_ops + report.total_fallback_ops;
    assert!(total_ops > 0, "expected lifted instructions");
    let coverage: f64 = report.total_reconstructed_ops as f64 / total_ops as f64;
    eprintln!(
        "hermes v96 sample: fns={} with_body={} ops={}r/{}f coverage={:.2}%",
        report.function_count,
        report.functions_with_body,
        report.total_reconstructed_ops,
        report.total_fallback_ops,
        coverage * 100.0
    );

    assert_eq!(
        report.function_count, 8,
        "global plus seven authored functions"
    );
    assert_eq!(report.functions_with_body, 8);

    assert_eq!(
        report.total_fallback_ops, 0,
        "every opcode in this sample must have a real lowering rule (no fallback)"
    );
    assert!(
        (coverage - 1.0).abs() < f64::EPSILON,
        "op-coverage must be exactly 100% on the committed v96 sample, got {:.2}%",
        coverage * 100.0
    );

    for name in [
        "global",
        "add",
        "sumRange",
        "greet",
        "Counter",
        "main",
        "increment",
        "label",
    ] {
        assert!(
            report
                .functions
                .iter()
                .any(|f: &DecompiledFunction| f.name == name),
            "expected recovered function name {name} from the module string table; got {:?}",
            report
                .functions
                .iter()
                .map(|f: &DecompiledFunction| f.name.as_str())
                .collect::<Vec<&str>>()
        );
    }

    let fully_covered: usize = report
        .functions
        .iter()
        .filter(|f: &&DecompiledFunction| f.fallback_ops == 0)
        .count();
    let bar: serde_json::Value = published_bar(PUBLISHED_HEADING, PUBLISHED_BAR);
    let num: u64 = bar["num"]
        .as_u64()
        .expect("the hermes op-coverage bar must carry a numerator");
    let den: u64 = bar["den"]
        .as_u64()
        .expect("the hermes op-coverage bar must carry a denominator");
    let value: f64 = bar["value"]
        .as_f64()
        .expect("the hermes op-coverage bar must carry a numeric value");
    assert_eq!(
        u64::try_from(report.function_count).expect("function count fits u64"),
        den,
        "xtask/data/recovery.json publishes a denominator of {den} functions on this sample and \
         every document renders that number, but the module carries {}",
        report.function_count
    );
    assert!(
        u64::try_from(fully_covered).expect("covered fits u64") >= num,
        "recovery.json publishes {num} of {den} functions at full op coverage; this run lifted \
         {fully_covered} with zero fallback ops"
    );
    let derived: f64 = 100.0 * num as f64 / den as f64;
    assert!(
        (derived - value).abs() < 0.05,
        "the published value {value} disagrees with its own {num}/{den} = {derived:.4}"
    );
}

#[test]
fn hbc_v96_sample_recovers_correct_bodies() {
    let bytes: Vec<u8> = std::fs::read(sample("sample.hbc.v96")).expect("read v96 sample");
    let module: HermesModule = parse_hermes_module(&bytes).expect("parse v96 module");
    let report: DecompileReport = decompile_hermes_module(&module);

    let add: &DecompiledFunction = function(&report, "add");
    assert_eq!(add.param_count, 3, "add(a, b): this plus two params");
    assert_eq!(add.fallback_ops, 0);
    assert!(
        add.source.contains("function add(arg0, arg1)"),
        "add signature; src: {}",
        add.source
    );
    assert!(
        add.source.contains("return (arg0 + arg1);"),
        "add must recover the arithmetic body; src: {}",
        add.source
    );

    let greet: &DecompiledFunction = function(&report, "greet");
    assert_eq!(greet.fallback_ops, 0);
    assert!(
        greet.source.contains("\"disrobe-hermes-\""),
        "greet must recover its real string literal; src: {}",
        greet.source
    );
    assert!(
        greet
            .source
            .contains("return ((\"disrobe-hermes-\" + arg0) + \"!\");"),
        "greet must recover the concatenation chain; src: {}",
        greet.source
    );

    let sum_range: &DecompiledFunction = function(&report, "sumRange");
    assert_eq!(sum_range.fallback_ops, 0);
    assert!(
        sum_range.has_loop,
        "sumRange must recover its counted loop (back edge); src: {}",
        sum_range.source
    );
    assert!(
        sum_range.has_if,
        "sumRange must recover its loop condition; src: {}",
        sum_range.source
    );
    assert!(
        sum_range.block_count >= 3,
        "sumRange must split into multiple basic blocks; blocks: {}",
        sum_range.block_count
    );

    let increment: &DecompiledFunction = function(&report, "increment");
    assert_eq!(increment.fallback_ops, 0);
    assert!(
        increment.source.contains("this.value = (this.value + 1);"),
        "increment must recover the prototype-method field update; src: {}",
        increment.source
    );
    assert!(
        increment.source.contains("return this.value;"),
        "increment must recover its return; src: {}",
        increment.source
    );

    for f in &report.functions {
        assert!(
            !f.source.contains("Unknown_0x"),
            "no opcode in the v96 sample may be unknown; {} src: {}",
            f.name,
            f.source
        );
        assert!(
            !f.source.contains("<truncated>"),
            "no instruction stream in the v96 sample may truncate; {} src: {}",
            f.name,
            f.source
        );
    }
}

#[test]
fn hbc_v76_and_v84_parse_and_recover_names_across_versions() {
    for (file, expected_version) in [("sample.hbc.v84", 84u32), ("sample.hbc.v76", 76)] {
        let bytes: Vec<u8> = std::fs::read(sample(file)).unwrap_or_else(|_| panic!("read {file}"));
        assert_eq!(
            &bytes[8..12],
            &expected_version.to_le_bytes(),
            "{file} must be HBC version {expected_version}"
        );
        let module: HermesModule =
            parse_hermes_module(&bytes).unwrap_or_else(|_| panic!("parse {file}"));
        assert_eq!(module.header.version, expected_version);
        let report: DecompileReport = decompile_hermes_module(&module);
        assert_eq!(
            report.function_count, 8,
            "{file}: container parse recovers all functions"
        );
        for name in [
            "add",
            "sumRange",
            "greet",
            "Counter",
            "main",
            "increment",
            "label",
        ] {
            assert!(
                report
                    .functions
                    .iter()
                    .any(|f: &DecompiledFunction| f.name == name),
                "{file}: function name {name} must resolve from the string table across HBC versions; got {:?}",
                report
                    .functions
                    .iter()
                    .map(|f: &DecompiledFunction| f.name.as_str())
                    .collect::<Vec<&str>>()
            );
        }
    }
}
