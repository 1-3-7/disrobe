#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_shell::{BatchReport, reverse_batch};

fn corpus_path(relative: &str) -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &std::path::Path = manifest_dir
        .parent()
        .and_then(|p: &std::path::Path| p.parent())
        .expect("workspace root");
    workspace_root.join("corpus").join("shell").join(relative)
}

fn read_corpus(relative: &str) -> String {
    let p: PathBuf = corpus_path(relative);
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", p.display()))
}

#[test]
fn fixture_batch_baseline_round_trip() {
    let src: String = read_corpus("batch/baseline/hello.bat");
    let r: BatchReport = reverse_batch(&src);
    assert!(r.output.contains("echo hello world"));
}

#[test]
fn fixture_batch_call_technique_unwraps_var() {
    let src: String = read_corpus("batch/call/hello.bat");
    let r: BatchReport = reverse_batch(&src);
    assert!(r.set_substitutions >= 1, "batch report: {r:?}");
    assert!(
        r.output.contains("echo hello world"),
        "batch report output: {}",
        r.output
    );
}

#[test]
fn fixture_batch_caret_technique_preserved_text() {
    let src: String = read_corpus("batch/caret/hello.bat");
    let r: BatchReport = reverse_batch(&src);
    let lowered: String = r.output.to_ascii_lowercase();
    assert!(lowered.contains("echo"));
}

#[test]
fn fixture_batch_megafile_no_panic() {
    let src: String = read_corpus("batch/megafile/edge_cases.bat");
    let r: BatchReport = reverse_batch(&src);
    assert!(!r.output.is_empty());
}
