#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../disrobe-pass-jvm/tests/fixtures/implementors/classes")
}

#[cfg(feature = "jvm")]
#[test]
fn query_command_emits_jvm_implementors_as_text_and_json() {
    let binary: &str = env!("CARGO_BIN_EXE_disrobe");
    let input: PathBuf = fixture();
    let text = Command::new(binary)
        .args([
            "query",
            input.to_str().expect("utf8 path"),
            "implementors",
            "Limplementors/Root;",
        ])
        .output()
        .expect("run text query");
    assert!(
        text.status.success(),
        "{}",
        String::from_utf8_lossy(&text.stderr)
    );
    let stdout: String = String::from_utf8(text.stdout).expect("utf8 text");
    assert!(stdout.contains("Limplementors/Direct;  Limplementors/Direct; -> Limplementors/Root;"));
    assert!(stdout.contains("Limplementors/Leaf;  Limplementors/Leaf; -> Limplementors/Base; -> Limplementors/Middle; -> Limplementors/Root;"));
    let json = Command::new(binary)
        .args([
            "--json",
            "query",
            input.to_str().expect("utf8 path"),
            "implementors",
            "Limplementors/Root;",
        ])
        .output()
        .expect("run json query");
    assert!(
        json.status.success(),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).expect("parse json");
    let names: Vec<&str> = value["matches"]
        .as_array()
        .expect("matches")
        .iter()
        .map(|item| item["descriptor"].as_str().expect("descriptor"))
        .collect();
    assert_eq!(names, vec!["Limplementors/Direct;", "Limplementors/Leaf;"]);
}

#[cfg(feature = "jvm")]
#[test]
fn query_command_accepts_single_and_multidex_inputs() {
    let binary: &str = env!("CARGO_BIN_EXE_disrobe");
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../disrobe-pass-jvm/tests/fixtures/implementors");
    let single = Command::new(binary)
        .args([
            "--json",
            "query",
            base.join("Hierarchy-d8.dex").to_str().expect("utf8 path"),
            "implementors",
            "Limplementors/Root;",
        ])
        .output()
        .expect("run single dex query");
    assert!(
        single.status.success(),
        "{}",
        String::from_utf8_lossy(&single.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&single.stdout).expect("json")["matches"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    let directory = tempfile::tempdir().expect("directory");
    std::fs::copy(
        base.join("Hierarchy-d8.dex"),
        directory.path().join("classes.dex"),
    )
    .expect("copy first dex");
    std::fs::copy(
        base.join("Extra-d8.dex"),
        directory.path().join("classes2.dex"),
    )
    .expect("copy second dex");
    let multi = Command::new(binary)
        .args([
            "query",
            directory.path().to_str().expect("utf8 path"),
            "implementors",
            "Limplementors/Root;",
        ])
        .output()
        .expect("run multidex query");
    assert!(
        multi.status.success(),
        "{}",
        String::from_utf8_lossy(&multi.stderr)
    );
    let output = String::from_utf8(multi.stdout).expect("utf8 text");
    assert!(output.contains("Limplementors/Extra;"));
    assert!(output.contains("(3 match(es))"));
}

#[cfg(not(feature = "jvm"))]
#[test]
fn query_command_reports_disabled_jvm_support() {
    let binary: &str = env!("CARGO_BIN_EXE_disrobe");
    let output = Command::new(binary)
        .args([
            "query",
            fixture().to_str().expect("utf8 path"),
            "implementors",
            "Limplementors/Root;",
        ])
        .output()
        .expect("run query");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("JVM query support is not enabled"));
}
