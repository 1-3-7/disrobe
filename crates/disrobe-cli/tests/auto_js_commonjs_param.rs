#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SOURCE: &str = r#"(function(factory){if(typeof module==="object"&&module.exports){module.exports=factory(require("./math-utils"),require("./text-format"));}else{__root.output=factory(__root.mathUtils,__root.textFormat);}})(function(a,b){var result=a.sum(10,11);return b(result);});print(module.exports||__root.output);"#;

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
            if compact.contains("function(mathUtils,textFormat)")
                && compact.contains("mathUtils.sum(10,11)")
                && compact.contains("textFormat(result)")
            {
                return Some(source);
            }
        }
    }
    None
}

#[test]
fn auto_recovers_commonjs_umd_factory_parameter_names() {
    assert!(SOURCE.len() > 200);
    let input_scratch: disrobe_core::scratch::ScratchDir = scratch("auto-js-commonjs-input");
    let input: PathBuf = input_scratch.path().join("bundle.js");
    std::fs::write(&input, SOURCE).expect("write CommonJS UMD fixture");

    let output_scratch: disrobe_core::scratch::ScratchDir = scratch("auto-js-commonjs-output");
    let process: std::process::Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("auto")
        .arg(&input)
        .arg("--out")
        .arg(output_scratch.path())
        .arg("--max-depth")
        .arg("3")
        .arg("--capture-stages")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("failed to spawn disrobe auto: {error}"));
    assert!(
        process.status.success(),
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
    assert!(
        passes.contains(&"js.deob"),
        "auto must route the minified UMD source through js.deob: {passes:?}"
    );
    let recovered: String = find_recovered_source(output_scratch.path())
        .expect("captured js.deob output must contain both recovered dependency names");
    assert!(!recovered.contains("function(a,b)"));
}
