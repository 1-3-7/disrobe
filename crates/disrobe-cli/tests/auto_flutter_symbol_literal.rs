#![cfg(all(feature = "chain", feature = "mobile"))]
#![allow(clippy::expect_used, clippy::panic)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};

const SYMBOL_FIXTURE: &[u8] = include_bytes!(
    "../../disrobe-pass-mobile/tests/fixtures/flutter_symbol_dart_3_12_2/symbol_probe_arm64.so"
);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const PROCESS_CAPTURE_LIMIT: usize = 1_048_576;

#[test]
fn auto_routes_a_real_flutter_symbol_literal_to_mobile_recovery() {
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto_flutter_symbol_input")
            .expect("create Flutter Symbol input");
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto_flutter_symbol_output")
            .expect("create Flutter Symbol output");
    let input_path: PathBuf = input.path().join("libapp.so");
    std::fs::write(&input_path, SYMBOL_FIXTURE).expect("write Flutter Symbol fixture");
    let executable: PathBuf = PathBuf::from(env!("CARGO_BIN_EXE_disrobe"));
    let args: [OsString; 7] = [
        OsString::from("auto"),
        input_path.as_os_str().to_os_string(),
        OsString::from("--out"),
        output.path().as_os_str().to_os_string(),
        OsString::from("--max-depth"),
        OsString::from("2"),
        OsString::from("--capture-stages"),
    ];
    let process: CapturedOutput =
        run_captured(&executable, &args, PROCESS_TIMEOUT, PROCESS_CAPTURE_LIMIT)
            .expect("launch disrobe auto")
            .expect("disrobe auto exceeded its wall-clock bound");
    assert_eq!(
        process.exit_code,
        Some(0),
        "disrobe auto failed: {}",
        String::from_utf8_lossy(&process.stderr)
    );

    let chain_raw: String =
        std::fs::read_to_string(output.path().join("chain.json")).expect("read chain report");
    let chain: serde_json::Value = serde_json::from_str(&chain_raw).expect("parse chain report");
    assert!(
        chain["nodes"]
            .as_array()
            .expect("chain nodes")
            .iter()
            .any(|node: &serde_json::Value| node["pass"] == "mobile.classify")
    );

    let report_path: PathBuf = output.path().join("symbol-report.json");
    let decompile_args: [OsString; 7] = [
        OsString::from("flutter"),
        OsString::from("decompile"),
        input_path.as_os_str().to_os_string(),
        OsString::from("--out"),
        report_path.as_os_str().to_os_string(),
        OsString::from("--emit"),
        OsString::from("source,report"),
    ];
    let decompile: CapturedOutput = run_captured(
        &executable,
        &decompile_args,
        PROCESS_TIMEOUT,
        PROCESS_CAPTURE_LIMIT,
    )
    .expect("launch flutter decompile")
    .expect("flutter decompile exceeded its wall-clock bound");
    assert_eq!(
        decompile.exit_code,
        Some(0),
        "flutter decompile failed: {}",
        String::from_utf8_lossy(&decompile.stderr)
    );
    let source: String = std::fs::read_to_string(report_path.with_extension("recovered.dart"))
        .expect("read recovered pseudo-Dart");
    assert!(source.contains("Symbol(\"shipment.status\")"));
    let report: String = std::fs::read_to_string(report_path).expect("read Flutter AOT report");
    assert!(report.contains("Symbol(\\\"shipment.status\\\")"));
}
