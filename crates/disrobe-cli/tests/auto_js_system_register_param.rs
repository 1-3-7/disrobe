#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};

const SOURCE: &str =
    include_str!("../../disrobe-pass-js-deob/tests/fixtures/rollup_system_param/fixture.min.js");
const CLI_TIMEOUT: Duration = Duration::from_secs(30);
const CLI_CAPTURE: usize = 1usize << 20;

#[allow(clippy::disallowed_methods)]
fn scratch(purpose: &str) -> disrobe_core::scratch::ScratchDir {
    disrobe_core::scratch::ScratchDir::create(purpose).expect("create scratch directory")
}

fn find_recovered_source(directory: &Path) -> Option<String> {
    let entries: std::fs::ReadDir = std::fs::read_dir(directory).ok()?;
    for entry in entries.filter_map(Result::ok) {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            if let Some(source) = find_recovered_source(&path) {
                return Some(source);
            }
            continue;
        }
        if let Ok(source) = std::fs::read_to_string(&path) {
            let compact: String = source
                .chars()
                .filter(|character: &char| !character.is_whitespace())
                .collect();
            if compact.contains("function(mathUtils){t=mathUtils.sum}")
                && compact.contains("function(textFormat){e=textFormat.default}")
            {
                return Some(source);
            }
        }
    }
    None
}

#[test]
fn auto_recovers_rollup_system_register_setter_parameter_names() {
    assert_eq!(SOURCE.len(), 213);
    assert_eq!(SOURCE.lines().count(), 1);
    let input_scratch: disrobe_core::scratch::ScratchDir = scratch("auto-js-system-input");
    let input: PathBuf = input_scratch.path().join("bundle.js");
    std::fs::write(&input, SOURCE).expect("write Rollup System.register fixture");

    let output_scratch: disrobe_core::scratch::ScratchDir = scratch("auto-js-system-output");
    let args: Vec<OsString> = vec![
        OsString::from("auto"),
        input.as_os_str().to_owned(),
        OsString::from("--out"),
        output_scratch.path().as_os_str().to_owned(),
        OsString::from("--max-depth"),
        OsString::from("3"),
        OsString::from("--capture-stages"),
    ];
    let arg_refs: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    let process: CapturedOutput = run_captured(
        Path::new(env!("CARGO_BIN_EXE_disrobe")),
        &arg_refs,
        CLI_TIMEOUT,
        CLI_CAPTURE,
    )
    .expect("spawn disrobe auto")
    .expect("disrobe auto must finish within the timeout");
    assert_eq!(
        process.exit_code,
        Some(0),
        "disrobe auto failed: {}",
        String::from_utf8_lossy(&process.stderr)
    );

    let chain_raw: String = std::fs::read_to_string(output_scratch.path().join("chain.json"))
        .expect("read auto chain.json");
    let chain: serde_json::Value = serde_json::from_str(&chain_raw).expect("parse auto chain.json");
    let passes: Vec<&str> = chain
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .expect("chain.json nodes")
        .iter()
        .filter_map(|node: &serde_json::Value| node.get("pass").and_then(serde_json::Value::as_str))
        .collect();
    assert!(passes.contains(&"js.deob"), "auto pass list: {passes:?}");
    let recovered: String = find_recovered_source(output_scratch.path())
        .expect("captured js.deob output must contain both recovered setter names");
    assert!(!recovered.contains("function(s){t=s.sum}"));
}
