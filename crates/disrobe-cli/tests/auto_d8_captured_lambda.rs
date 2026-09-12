#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use disrobe_core::scratch::ScratchDir;

const JVM_PASS_ID: &str = "jvm.classify";

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("corpus/jvm/desugar-lambda/CapturedLambdaProbe-min21.dex")
}

fn recovered_sources(root: &Path) -> Vec<String> {
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut sources: Vec<String> = Vec::new();
    while let Some(directory) = pending.pop() {
        let entries: std::fs::ReadDir =
            std::fs::read_dir(&directory).expect("read recovery directory");
        for entry in entries {
            let path: PathBuf = entry.expect("read recovery entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(std::ffi::OsStr::to_str) == Some("java") {
                sources.push(std::fs::read_to_string(path).expect("read recovered Java source"));
            }
        }
    }
    sources.sort();
    sources
}

fn run(args: &[&str], output: &Path) -> Output {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_disrobe"));
    command
        .args(args)
        .arg("--out")
        .arg(output)
        .stdin(Stdio::null());
    command.output().expect("spawn disrobe")
}

fn joined_sources(root: &Path) -> String {
    recovered_sources(root).join("\n")
}

#[test]
fn registered_auto_and_dedicated_callers_recover_the_real_d8_captured_lambda() {
    assert!(
        disrobe_passes::registered_pass_ids().contains(&JVM_PASS_ID),
        "the JVM pass must remain registered"
    );
    let input: PathBuf = fixture();
    assert!(input.is_file(), "missing D8 fixture: {}", input.display());

    let automatic: ScratchDir =
        ScratchDir::create("auto-d8-captured-lambda").expect("create automatic output");
    let input_text: String = input.to_string_lossy().into_owned();
    let automatic_output: Output = run(
        &[
            "auto",
            input_text.as_str(),
            "--max-depth",
            "3",
            "--capture-stages",
        ],
        automatic.path(),
    );
    assert!(
        automatic_output.status.success(),
        "disrobe auto failed: {}",
        String::from_utf8_lossy(&automatic_output.stderr)
    );
    let chain_text: String = std::fs::read_to_string(automatic.path().join("chain.json"))
        .expect("read automatic chain report");
    let chain: serde_json::Value = serde_json::from_str(&chain_text).expect("parse chain report");
    let passes: Vec<&str> = chain
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .expect("chain nodes")
        .iter()
        .filter_map(|node: &serde_json::Value| node.get("pass")?.as_str())
        .collect();
    assert!(passes.contains(&JVM_PASS_ID), "passes: {passes:?}");
    let automatic_source: String = joined_sources(automatic.path());

    let dedicated: ScratchDir =
        ScratchDir::create("dedicated-d8-captured-lambda").expect("create dedicated output");
    let dedicated_output: Output = run(
        &["jvm", "decompile", input_text.as_str(), "--emit", "source"],
        dedicated.path(),
    );
    assert!(
        dedicated_output.status.success(),
        "disrobe jvm decompile failed: {}",
        String::from_utf8_lossy(&dedicated_output.stderr)
    );
    let dedicated_source: String = joined_sources(dedicated.path());

    assert_eq!(automatic_source, dedicated_source);
    assert!(automatic_source.contains("->"), "{automatic_source}");
    assert!(
        !automatic_source.contains("InternalSyntheticLambda"),
        "{automatic_source}"
    );
    assert!(
        !automatic_source.contains("new CapturedLambdaProbe$_"),
        "{automatic_source}"
    );
}
