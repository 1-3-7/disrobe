#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../disrobe-binfmt/tests/fixtures/lzh/level3/h3_subdir.lzh")
}

fn collect_members(root: &Path, members: &mut Vec<Vec<u8>>) {
    let entries: std::fs::ReadDir = std::fs::read_dir(root).expect("read auto output directory");
    for entry in entries {
        let path: PathBuf = entry.expect("read auto output entry").path();
        if path.is_dir() {
            collect_members(&path, members);
        } else if path.file_name().and_then(std::ffi::OsStr::to_str) == Some("HELLO.TXT") {
            members.push(std::fs::read(path).expect("read recovered LZH member"));
        }
    }
}

fn recover_batch(jobs: u32) -> Vec<Vec<u8>> {
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-lzh-level3-input")
            .expect("create batch input");
    for name in ["first.lzh", "second.lzh"] {
        std::fs::copy(fixture(), input.path().join(name)).expect("stage LZH fixture");
    }
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-lzh-level3-output")
            .expect("create batch output");
    let process: std::process::Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("auto")
        .arg(input.path())
        .arg("--out")
        .arg(output.path())
        .arg("--jobs")
        .arg(jobs.to_string())
        .arg("--max-depth")
        .arg("3")
        .arg("--capture-stages")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("spawn batch auto: {error}"));
    assert!(
        process.status.success(),
        "disrobe auto failed for jobs={jobs}: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    let manifest: String =
        std::fs::read_to_string(output.path().join("manifest.json")).expect("read batch manifest");
    let document: serde_json::Value =
        serde_json::from_str(&manifest).expect("parse batch manifest");
    assert_eq!(document["summary"]["processed"], 2);
    let mut members: Vec<Vec<u8>> = Vec::new();
    collect_members(output.path(), &mut members);
    members.sort();
    members
}

#[test]
fn auto_recovers_level3_lzh_members_identically_at_jobs_one_and_four() {
    let serial: Vec<Vec<u8>> = recover_batch(1);
    let parallel: Vec<Vec<u8>> = recover_batch(4);
    assert_eq!(serial, parallel);
    assert_eq!(serial, vec![b"hello world!\r\n".to_vec(); 2]);
}

#[test]
fn extract_command_recovers_the_level3_member_tree() {
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("extract-lzh-level3-output")
            .expect("create extract output");
    let process: std::process::Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("extract")
        .arg(fixture())
        .arg("--out")
        .arg(output.path())
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("spawn direct extraction: {error}"));
    assert!(
        process.status.success(),
        "disrobe extract failed: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    assert_eq!(
        std::fs::read(output.path().join("subdir/subdir2/HELLO.TXT"))
            .expect("read direct LZH output"),
        b"hello world!\r\n"
    );
}
