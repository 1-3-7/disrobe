#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

#[path = "support/hermes_production_bundle.rs"]
#[allow(clippy::redundant_pub_crate, dead_code, clippy::panic)]
mod hermes_production_bundle;

use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{
    DeclineCount, DecompileReport, DecompiledFunction, HermesModule, decompile_hermes_function,
    decompile_hermes_module, parse_hermes_module,
};
use hermes_production_bundle::{PUBLISHED_FUNCTION_COUNT, load_bundle};

const SAMPLED_FUNCTIONS: usize = 2_000;
const SAMPLE_FALLBACK_OP_CEILING: usize = 19;
const MODULE_OP_TOTAL: usize = 5_765_066;
const MODULE_FALLBACK_OP_CEILING: usize = 9_531;

fn hello_fixture() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("hermes")
        .join("hello")
        .join("index.android.bundle")
}

#[test]
fn hello_bundle_recovers_readable_constructs() {
    let path: PathBuf = hello_fixture();
    let bytes: Vec<u8> = std::fs::read(&path).expect("read hello bundle");
    let module: HermesModule = parse_hermes_module(&bytes).expect("parse hello module");
    let report: DecompileReport = decompile_hermes_module(&module);

    let total_ops: usize = report.total_reconstructed_ops + report.total_fallback_ops;
    let recovery: f64 = if total_ops == 0 {
        0.0
    } else {
        report.total_reconstructed_ops as f64 / total_ops as f64
    };
    eprintln!(
        "hello: version={} fns={} body={} ops={}r/{}f recovery={:.1}%",
        report.hermes_version,
        report.function_count,
        report.functions_with_body,
        report.total_reconstructed_ops,
        report.total_fallback_ops,
        recovery * 100.0
    );

    let entry: &DecompiledFunction = report
        .functions
        .iter()
        .find(|f: &&DecompiledFunction| f.name == "disrobeHermesEntry")
        .expect("entry function present");
    eprintln!("--- disrobeHermesEntry ---\n{}", entry.source);

    assert!(
        entry.source.contains("\"disrobe-hermes-token\""),
        "expected recovered string literal; src: {}",
        entry.source
    );
    assert!(
        entry.source.contains("print"),
        "expected print call; src: {}",
        entry.source
    );
    assert!(
        recovery >= 0.80,
        "expected >=80% op recovery on hello bundle, got {:.1}%",
        recovery * 100.0
    );
}

#[test]
fn hello_call2_argument_is_the_real_register_value() {
    let bytes: Vec<u8> = std::fs::read(hello_fixture()).expect("read hello bundle");
    let module: HermesModule = parse_hermes_module(&bytes).expect("parse hello module");

    let token_in_table: bool = (0..module.header.string_count)
        .filter_map(|id: u32| module.string_by_global_id(id))
        .any(|s: &str| s == "disrobe-hermes-token");
    assert!(
        token_in_table,
        "oracle precondition: token literal must exist in the module string table"
    );

    let report: DecompileReport = decompile_hermes_module(&module);
    let entry: &DecompiledFunction = report
        .functions
        .iter()
        .find(|f: &&DecompiledFunction| f.name == "disrobeHermesEntry")
        .expect("entry function present");

    assert!(
        entry.source.contains("print(\"disrobe-hermes-token\")"),
        "Call2 argument must be the real register value from the raw bytecode \
         (LoadConstString of the token), not a placeholder; src: {}",
        entry.source
    );
    assert!(
        !entry.source.contains("<arg?>"),
        "Call2 fully recovers its arguments and must not mark them unrecovered; src: {}",
        entry.source
    );
    assert!(
        !entry.source.contains("a0") && !entry.source.contains("a1"),
        "call arguments must never be fabricated placeholder names; src: {}",
        entry.source
    );
}

#[test]
fn discord_bundle_decompiles_most_functions() {
    let Some(bytes): Option<Vec<u8>> = load_bundle("the sampled production-bundle decompile")
    else {
        return;
    };
    let module: HermesModule = parse_hermes_module(&bytes).expect("parse discord module");
    assert_eq!(
        module.functions.len(),
        PUBLISHED_FUNCTION_COUNT,
        "the sampled figures below were measured over this exact bundle"
    );

    let sample: usize = SAMPLED_FUNCTIONS;
    let mut emitted: usize = 0;
    let mut with_if: usize = 0;
    let mut with_loop: usize = 0;
    let mut with_try: usize = 0;
    let mut reconstructed: usize = 0;
    let mut fallback: usize = 0;
    for i in 0..sample {
        let f: DecompiledFunction = decompile_hermes_function(&module, i);
        if f.instruction_count > 0 && f.fallback_ops < f.instruction_count {
            emitted += 1;
        }
        with_if += usize::from(f.has_if);
        with_loop += usize::from(f.has_loop);
        with_try += usize::from(f.has_try_catch);
        reconstructed += f.reconstructed_ops;
        fallback += f.fallback_ops;
    }
    let ratio: f64 = emitted as f64 / sample as f64;
    eprintln!(
        "discord decompile sample={} emitted={} ({:.1}%) if={} loop={} try={} ops={}r/{}f",
        sample,
        emitted,
        ratio * 100.0,
        with_if,
        with_loop,
        with_try,
        reconstructed,
        fallback
    );
    assert_eq!(
        emitted, sample,
        "every one of the {sample} sampled functions emitted pseudo-JS when this figure was \
         measured, so anything short of all of them is a regression"
    );
    assert!(
        fallback <= SAMPLE_FALLBACK_OP_CEILING,
        "the sampled window left {SAMPLE_FALLBACK_OP_CEILING} ops unlowered when this figure was \
         measured, got {fallback} of {} total",
        reconstructed + fallback
    );
    assert!(with_if > 0, "expected some functions with conditionals");
}

#[test]
fn discord_decompile_module_report_consistent() {
    let Some(bytes): Option<Vec<u8>> = load_bundle("the whole-module production-bundle decompile")
    else {
        return;
    };
    let module: HermesModule = parse_hermes_module(&bytes).expect("parse");
    let report: DecompileReport = decompile_hermes_module(&module);
    assert_eq!(report.function_count, PUBLISHED_FUNCTION_COUNT);
    assert_eq!(report.function_count, module.functions.len());
    assert_eq!(report.functions.len(), module.functions.len());
    assert_eq!(
        report.functions_with_body, PUBLISHED_FUNCTION_COUNT,
        "every function header in this bundle owns a non-empty body, so a report that bodies fewer \
         of them has lost some"
    );
    assert!(report.total_reconstructed_ops > report.total_fallback_ops);
    assert!(
        report.total_fallback_ops <= MODULE_FALLBACK_OP_CEILING,
        "the whole-module decompile left {MODULE_FALLBACK_OP_CEILING} ops unlowered when this \
         figure was measured, got {}",
        report.total_fallback_ops
    );

    let total_ops: usize = report.total_reconstructed_ops + report.total_fallback_ops;
    assert_eq!(
        total_ops, MODULE_OP_TOTAL,
        "the op denominator is pinned to this bundle, so a run that decodes fewer instructions \
         scores worse instead of shrinking what it is measured against"
    );
    let ratio: f64 = report.total_reconstructed_ops as f64 / total_ops as f64;
    eprintln!(
        "discord full-module op-reconstruction: {}r/{}f ratio={:.2}%",
        report.total_reconstructed_ops,
        report.total_fallback_ops,
        ratio * 100.0
    );
    assert!(
        ratio >= 0.998,
        "expected >=99.8% whole-module op-coverage (a lowering rule is present; this is coverage, not decompile correctness), got {:.2}%",
        ratio * 100.0
    );

    let declined: usize = report
        .structure_declines
        .iter()
        .map(|count: &DeclineCount| count.functions)
        .sum();
    assert_eq!(
        report.structured_functions + declined,
        report.functions_with_body,
        "structured plus declined accounts for every bodied function, so a body can never fall out \
         of both columns; declines {:?}",
        report.structure_declines
    );
    let structured_ratio: f64 =
        report.structured_functions as f64 / report.functions_with_body as f64;
    eprintln!(
        "discord full-module structuring: {} of {} bodied functions reach structured control flow ({:.2}%); declined by reason {:?}",
        report.structured_functions,
        report.functions_with_body,
        structured_ratio * 100.0,
        report.structure_declines
    );
    for recovered in &report.functions {
        if recovered.structure_decline.is_none() {
            assert!(
                !recovered.source.contains("goto "),
                "{}: claims structure while carrying goto edges",
                recovered.name
            );
        }
    }
}
