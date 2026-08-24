#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use disrobe_core::scratch::ScratchDir;

const JVM_PASS_ID: &str = "jvm.classify";

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../disrobe-pass-jvm/tests/fixtures/d8_constructor_delegate/ConstructorDelegateProbe-min21.dex")
}

fn sources(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut found: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).expect("read recovery directory") {
            let path: PathBuf = entry.expect("read recovery entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(std::ffi::OsStr::to_str) == Some("java") {
                let relative: String = path
                    .strip_prefix(root)
                    .expect("recovered source stays under output")
                    .to_string_lossy()
                    .replace('\\', "/");
                found.insert(relative, std::fs::read(path).expect("read Java source"));
            }
        }
    }
    found
}

fn source_bytes(sources: &BTreeMap<String, Vec<u8>>) -> Vec<Vec<u8>> {
    let mut bytes: Vec<Vec<u8>> = sources.values().cloned().collect();
    bytes.sort();
    bytes
}

fn run(args: &[&str], output: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .args(args)
        .arg("--out")
        .arg(output)
        .stdin(Stdio::null())
        .output()
        .expect("spawn disrobe")
}

fn auto_sources(jobs: u32) -> BTreeMap<String, Vec<u8>> {
    let output: ScratchDir =
        ScratchDir::create("auto-d8-constructor-delegate").expect("create automatic output");
    let input: String = fixture().to_string_lossy().into_owned();
    let job_count: String = jobs.to_string();
    let result: Output = run(
        [
            "auto",
            input.as_str(),
            "--jobs",
            job_count.as_str(),
            "--max-depth",
            "3",
            "--capture-stages",
        ]
        .as_slice(),
        output.path(),
    );
    assert!(
        result.status.success(),
        "disrobe auto failed at jobs={jobs}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let chain: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.path().join("chain.json")).expect("read chain report"),
    )
    .expect("parse chain report");
    let passes: Vec<&str> = chain["nodes"]
        .as_array()
        .expect("chain nodes")
        .iter()
        .filter_map(|node: &serde_json::Value| node["pass"].as_str())
        .collect();
    assert!(passes.contains(&JVM_PASS_ID), "passes: {passes:?}");
    sources(output.path())
}

#[test]
fn auto_d8_constructor_delegate_matches_the_dedicated_route_at_jobs_one_and_four() {
    let input: PathBuf = fixture();
    assert!(input.is_file(), "missing fixture: {}", input.display());
    let input_text: String = input.to_string_lossy().into_owned();
    let dedicated: ScratchDir =
        ScratchDir::create("dedicated-d8-constructor-delegate").expect("create dedicated output");
    let result: Output = run(
        ["jvm", "decompile", input_text.as_str(), "--emit", "source"].as_slice(),
        dedicated.path(),
    );
    assert!(
        result.status.success(),
        "disrobe jvm decompile failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let dedicated_sources: BTreeMap<String, Vec<u8>> = sources(dedicated.path());
    let jobs_one: BTreeMap<String, Vec<u8>> = auto_sources(1);
    let jobs_four: BTreeMap<String, Vec<u8>> = auto_sources(4);
    assert_eq!(jobs_one, jobs_four);
    assert_eq!(source_bytes(&jobs_one), source_bytes(&dedicated_sources));
    let joined: String = String::from_utf8(
        source_bytes(&dedicated_sources)
            .into_iter()
            .flatten()
            .collect(),
    )
    .expect("recovered sources are UTF-8");
    assert!(joined.contains("this(((fixtures.constructor.InputPair) arg0).left"));
}
