#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unreachable_pub,
    clippy::print_stdout,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]

use disrobe_pass_php::{LoaderSink, RecoveryStage, peel_modern_loader, recover_php};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/php_real_chains"
);

fn load(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}/{name}")).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn recover(name: &str) -> String {
    let bytes: Vec<u8> = load(name);
    let report = recover_php(&bytes, None).unwrap_or_else(|e| panic!("recover {name}: {e}"));
    assert_eq!(
        report.stage,
        RecoveryStage::EvalChainPeeled,
        "{name}: expected an eval-chain recovery, got {:?}; notes {:?}",
        report.stage,
        report.notes
    );
    report.output
}

fn assert_recovers_original(name: &str) {
    let out: String = recover(name);
    assert!(
        out.contains("function greet") && out.contains("echo greet('world')"),
        "{name}: recovered output is missing the original source body; got:\n{out}"
    );
    assert!(
        !out.contains("base64_decode")
            && !out.contains("gzinflate")
            && !out.contains("gzuncompress")
            && !out.contains("gzdecode")
            && !out.contains("str_rot13")
            && !out.contains("strrev")
            && !out.contains("hex2bin")
            && !out.contains("implode")
            && !out.contains("eval(")
            && !out.contains("create_function")
            && !out.contains("pack("),
        "{name}: a decode primitive survived in the recovered output; got:\n{out}"
    );
}

#[test]
fn hex2bin_eval_recovers() {
    assert_recovers_original("x_hex2bin.php");
}

#[test]
fn arithmetic_folded_function_name_recovers() {
    assert_recovers_original("x_arith_fname.php");
}

#[test]
fn string_concatenated_function_name_recovers() {
    assert_recovers_original("x_concat_fname.php");
}

#[test]
fn implode_of_array_function_name_recovers() {
    assert_recovers_original("x_implode_array.php");
}

#[test]
fn substr_carved_function_name_recovers() {
    assert_recovers_original("x_substr_fname.php");
}

#[test]
fn globals_curly_variable_indirection_recovers() {
    assert_recovers_original("x_globals_curly.php");
}

#[test]
fn globals_chained_decode_indirection_recovers() {
    assert_recovers_original("x_globals_chain.php");
}

#[test]
fn strrev_rot13_gzinflate_arbitrary_order_recovers() {
    assert_recovers_original("x_strrev_rot13_gz.php");
}

#[test]
fn double_gzinflate_base64_nesting_recovers() {
    assert_recovers_original("x_double_gz_b64.php");
}

#[test]
fn create_function_legacy_sink_recovers() {
    assert_recovers_original("x_createfunc.php");
}

#[test]
fn create_function_loader_reports_dedicated_sink() {
    let bytes: Vec<u8> = load("x_createfunc.php");
    let report = peel_modern_loader(&bytes, disrobe_pass_php::DEFAULT_LOADER_DEPTH)
        .expect("create_function loader recovery");
    assert_eq!(report.sink, LoaderSink::CreateFunction);
    assert!(
        report
            .recovered
            .windows(14)
            .any(|w: &[u8]| w == b"function greet"),
        "create_function body must carry the recovered source"
    );
}
