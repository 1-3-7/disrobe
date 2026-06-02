#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{
    DecompileReport, DecompiledFunction, HermesModule, decompile_hermes_function,
    decompile_hermes_module, parse_hermes_module,
};

fn discord_fixture() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("hermes")
        .join("discord")
        .join("index.android.bundle")
}

#[test]
fn discord_bundle_decompiles_most_functions() {
    let path: PathBuf = discord_fixture();
    if !path.exists() {
        eprintln!("skip: discord fixture missing at {:?}", path);
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&path).expect("read discord bundle");
    let module: HermesModule = parse_hermes_module(&bytes).expect("parse discord module");

    let sample: usize = 2_000.min(module.functions.len());
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
    assert!(
        ratio >= 0.80,
        "expected >=80% of sampled functions to emit pseudo-JS, got {:.1}%",
        ratio * 100.0
    );
    assert!(with_if > 0, "expected some functions with conditionals");
}

#[test]
fn discord_decompile_module_report_consistent() {
    let path: PathBuf = discord_fixture();
    if !path.exists() {
        eprintln!("skip: discord fixture missing");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&path).expect("read");
    let module: HermesModule = parse_hermes_module(&bytes).expect("parse");
    let report: DecompileReport = decompile_hermes_module(&module);
    assert_eq!(report.function_count, module.functions.len());
    assert_eq!(report.functions.len(), module.functions.len());
    assert!(report.functions_with_body > 0);
    assert!(report.total_reconstructed_ops > report.total_fallback_ops);
}
