#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("corpus/jvm/desugar-core/CoreLibraryProbe-min21.apk")
}

fn dex_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("corpus/jvm/desugar-core/CoreLibraryProbe-min21.dex")
}

fn multidex_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("corpus/jvm/desugar-core/CoreLibraryProbe-min21-multidex.apk")
}

fn expected_source() -> String {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("corpus/jvm/desugar-core/CoreLibraryProbe.recovered.java.txt");
    std::fs::read_to_string(path).expect("read expected recovered source")
}

fn recovered_source(root: &Path, declaration: &str) -> Option<String> {
    let entries: std::fs::ReadDir = std::fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            if let Some(source) = recovered_source(&path, declaration) {
                return Some(source);
            }
        } else if path.extension().and_then(std::ffi::OsStr::to_str) == Some("java") {
            let source: String = std::fs::read_to_string(&path).ok()?;
            if source.contains(declaration) {
                return Some(source);
            }
        }
    }
    None
}

fn recovered_sources(root: &Path, declaration: &str, sources: &mut Vec<String>) {
    let entries: std::fs::ReadDir = std::fs::read_dir(root).expect("read recovery directory");
    for entry in entries {
        let path: PathBuf = entry.expect("read recovery entry").path();
        if path.is_dir() {
            recovered_sources(&path, declaration, sources);
        } else if path.extension().and_then(std::ffi::OsStr::to_str) == Some("java") {
            let source: String =
                std::fs::read_to_string(&path).expect("read recovered Java source");
            if source.contains(declaration) {
                sources.push(source);
            }
        }
    }
}

fn batch_sources(jobs: u32) -> Vec<String> {
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-d8-core-library-batch-input")
            .expect("create batch input directory");
    for name in ["probe-a.apk", "probe-b.apk"] {
        std::fs::copy(fixture(), input.path().join(name)).expect("stage batch APK");
    }
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-d8-core-library-batch-output")
            .expect("create batch output directory");
    let process: std::process::Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("auto")
        .arg(input.path())
        .arg("--out")
        .arg(output.path())
        .arg("--jobs")
        .arg(jobs.to_string())
        .arg("--max-depth")
        .arg("4")
        .arg("--capture-stages")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("spawn batch auto: {error}"));
    assert!(
        process.status.success(),
        "disrobe auto batch failed for jobs={jobs}: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    let mut sources: Vec<String> = Vec::new();
    recovered_sources(output.path(), "public class CoreLibraryProbe", &mut sources);
    sources.sort();
    assert_eq!(
        sources.len(),
        2,
        "recover both batch Java compilation units"
    );
    sources
}

fn auto_source(label: &str, input: &Path) -> String {
    assert!(
        input.is_file(),
        "tracked D8 APK is missing: {}",
        input.display()
    );
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(label).expect("create output directory");
    let process: std::process::Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("auto")
        .arg(input)
        .arg("--out")
        .arg(output.path())
        .arg("--max-depth")
        .arg("4")
        .arg("--capture-stages")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("spawn disrobe auto: {error}"));
    assert!(
        process.status.success(),
        "disrobe auto failed: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    let chain_text: String =
        std::fs::read_to_string(output.path().join("chain.json")).expect("read chain report");
    let chain: serde_json::Value = serde_json::from_str(&chain_text).expect("parse chain report");
    let passes: Vec<&str> = chain
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .expect("chain nodes")
        .iter()
        .filter_map(|node: &serde_json::Value| node.get("pass")?.as_str())
        .collect();
    assert!(passes.contains(&"mobile.classify"), "passes: {passes:?}");
    assert!(passes.contains(&"jvm.classify"), "passes: {passes:?}");
    if input == multidex_fixture() {
        recovered_source(output.path(), "public class SecondaryProbe")
            .expect("recover the secondary multidex Java compilation unit");
    }
    recovered_source(output.path(), "public class CoreLibraryProbe")
        .expect("recover Java compilation unit")
}

#[test]
fn auto_routes_the_real_d8_apk_and_recovers_original_core_library_calls() {
    let input: PathBuf = fixture();
    let source: String = auto_source("auto-d8-core-library", &input);
    let multidex_source: String = auto_source("auto-d8-core-library-multidex", &multidex_fixture());
    assert_eq!(source, expected_source());
    assert_eq!(multidex_source, source);
    let single_job_sources: Vec<String> = batch_sources(1);
    let four_job_sources: Vec<String> = batch_sources(4);
    assert_eq!(single_job_sources, four_job_sources);
    assert!(
        single_job_sources
            .iter()
            .all(|recovered: &String| recovered == &source)
    );
    for generated in ["j$.", "$-EL", "$-CC", "DesugarTimeUnit"] {
        assert!(
            !source.contains(generated),
            "retained {generated}:\n{source}"
        );
    }
    assert!(source.contains("java.time.Duration.ofMinutes"), "{source}");
    assert!(
        source.contains("java.util.concurrent.TimeUnit.SECONDS.convert"),
        "{source}"
    );

    for (label, dedicated_input) in [
        ("jvm-d8-core-library-dex", dex_fixture()),
        ("jvm-d8-core-library-apk", fixture()),
    ] {
        let dedicated_output: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(label)
                .expect("create dedicated output directory");
        let dedicated: std::process::Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
            .arg("jvm")
            .arg("decompile")
            .arg(dedicated_input)
            .arg("--out")
            .arg(dedicated_output.path())
            .arg("--emit")
            .arg("source")
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|error: std::io::Error| panic!("spawn jvm decompile: {error}"));
        assert!(
            dedicated.status.success(),
            "jvm decompile failed: {}",
            String::from_utf8_lossy(&dedicated.stderr)
        );
        let dedicated_source: String =
            recovered_source(dedicated_output.path(), "public class CoreLibraryProbe")
                .expect("read dedicated Java source");
        assert_eq!(dedicated_source, source);
    }
}
