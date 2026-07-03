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
