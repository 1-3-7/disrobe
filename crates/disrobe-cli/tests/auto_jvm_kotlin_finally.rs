#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};

const KOTLIN_FINALLY_NESTED_CLASS: &[u8] = include_bytes!(
    "../../disrobe-pass-jvm/tests/fixtures/kotlin_finally_nested/FinallyNested.class"
);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(20);
const PROCESS_CAPTURE_LIMIT: usize = 1_048_576;

fn recovered_java(directory: &Path) -> Option<String> {
    let mut pending: Vec<PathBuf> = vec![directory.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in std::fs::read_dir(current).ok()?.filter_map(Result::ok) {
            let path: PathBuf = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path
                .extension()
                .is_some_and(|extension| extension == "java")
            {
                return std::fs::read_to_string(path).ok();
            }
        }
    }
    None
}

#[test]
fn auto_routes_kotlin_fallthrough_finally_with_nested_try() {
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto_jvm_kotlin_finally_input")
            .expect("create Kotlin input directory");
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto_jvm_kotlin_finally_output")
            .expect("create Kotlin output directory");
    let class_path: PathBuf = input.path().join("FinallyNested.class");
    std::fs::write(&class_path, KOTLIN_FINALLY_NESTED_CLASS).expect("write Kotlin fixture");
    let executable: PathBuf = PathBuf::from(env!("CARGO_BIN_EXE_disrobe"));
    let args: [OsString; 7] = [
        OsString::from("auto"),
        class_path.as_os_str().to_os_string(),
        OsString::from("--out"),
        output.path().as_os_str().to_os_string(),
        OsString::from("--max-depth"),
        OsString::from("3"),
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
        std::fs::read_to_string(output.path().join("chain.json")).expect("read auto chain report");
    let chain: serde_json::Value =
        serde_json::from_str(&chain_raw).expect("parse auto chain report");
    let passes: Vec<&str> = chain
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .expect("chain nodes")
        .iter()
        .filter_map(|node: &serde_json::Value| node.get("pass").and_then(serde_json::Value::as_str))
        .collect();
    assert!(
        passes.contains(&"jvm.classify"),
        "auto did not route the Kotlin class through the registered JVM pass: {passes:?}"
    );

    let source: String = recovered_java(output.path()).expect("auto emitted recovered Java");
    assert!(
        source.contains(" compute("),
        "compute method is absent:\n{source}"
    );
    assert!(
        source.contains("finally {"),
        "finally body is absent:\n{source}"
    );
    assert!(
        source.contains("catch (ArithmeticException"),
        "nested typed catch is absent:\n{source}"
    );
    assert!(
        !source.contains("not recovered:") && !source.contains("catch (Throwable"),
        "auto emitted a refusal or generic catch:\n{source}"
    );
}
