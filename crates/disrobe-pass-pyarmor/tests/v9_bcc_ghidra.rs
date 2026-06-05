#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::PathBuf;

use disrobe_pass_pyarmor::{BccArch, lift_bcc_native};

#[test]
fn v9_bcc_lift_empty_blob_errors() {
    let missing: PathBuf = std::env::temp_dir().join("disrobe-no-ghidra-bcc-empty");
    let err: disrobe_pass_pyarmor::Error =
        lift_bcc_native(&[], BccArch::WinX64, &missing).unwrap_err();
    let msg: String = format!("{err}");
    assert!(msg.contains("DR-PYARM-0060") || msg.contains("empty"));
}

#[test]
fn v9_bcc_lift_missing_ghidra_yields_ghidra_missing() {
    let missing: PathBuf = std::env::temp_dir().join("disrobe-no-ghidra-bcc-fixture");
    let _ = std::fs::remove_dir_all(&missing);
    let blob: Vec<u8> = (0..512u32).map(|i| (i & 0xff) as u8).collect();
    let err: disrobe_pass_pyarmor::Error =
        lift_bcc_native(&blob, BccArch::LinuxX64, &missing).unwrap_err();
    let msg: String = format!("{err}");
    assert!(
        msg.contains("DR-PYARM-0051") || msg.contains("ghidra"),
        "expected ghidra-missing error, got: {msg}"
    );
}

#[test]
fn v9_bcc_lift_arch_label_round_trips() {
    assert_eq!(BccArch::WinX64.label(), "win-x64");
    assert_eq!(BccArch::LinuxX64.label(), "linux-x64");
    assert_eq!(BccArch::DarwinArm64.label(), "darwin-arm64");
}

#[test]
fn v9_bcc_corpus_fixture_when_baked() {
    let here: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let corpus: PathBuf = here
        .parent()
        .expect("crates")
        .parent()
        .expect("repo")
        .join("corpus/python/pyarmor/v9-bcc");
    if !corpus.is_dir() {
        eprintln!(
            "skipped: v9-bcc corpus not baked at {} (bake the pyarmor corpus fixtures)",
            corpus.display()
        );
        return;
    }
    let walker: std::fs::ReadDir = std::fs::read_dir(&corpus).expect("read corpus");
    let mut found_wrapper: bool = false;
    for entry in walker.flatten() {
        let path: PathBuf = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("py")
            && let Ok(text) = std::fs::read_to_string(&path)
            && (text.contains("__pyarmor__") || text.contains("pyarmor_runtime"))
        {
            found_wrapper = true;
            break;
        }
    }
    assert!(
        found_wrapper,
        "expected at least one pyarmor wrapper py file in {}",
        corpus.display()
    );
}
