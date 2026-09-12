#![cfg(feature = "chain")]
#![cfg(not(feature = "jvm"))]
#![allow(clippy::disallowed_methods, clippy::expect_used, clippy::unwrap_used)]

mod common;

use std::path::PathBuf;
use std::process::{Command, Output};

use common::{Run, cli_binary, temp_dir};

#[test]
fn chain_only_auto_rejects_dalvik_export_before_processing_input() {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-dalvik-feature-gate");
    let missing: PathBuf = scratch.path().join("missing.dex");
    let out: PathBuf = scratch.path().join("out");
    let output: Output = Command::new(cli_binary())
        .arg("auto")
        .arg(&missing)
        .arg("--out")
        .arg(&out)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run chain-only disrobe auto");
    let run: Run = Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };

    assert_ne!(run.code, 0, "chain-only build accepted Dalvik export");
    assert!(run.stderr.contains("DR-CLI-0441"), "{}", run.stderr);
    assert!(!out.exists(), "feature gate created {}", out.display());
}
