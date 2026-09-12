#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const FIXTURE: &[u8] = include_bytes!("../../../corpus/binfmt/arc/methods.arc");

fn expected_members(copies: usize) -> Vec<(String, Vec<u8>)> {
    let mut members: Vec<(String, Vec<u8>)> = Vec::with_capacity(copies * 3);
    for _ in 0..copies {
        members.extend([
            ("METHOD5.BIN".to_owned(), b"ABABABAABABABA".to_vec()),
            (
                "METHOD6.BIN".to_owned(),
                b"AAAAABBBBBCCCCCAAAAABBBBB".to_vec(),
            ),
            (
                "METHOD7.BIN".to_owned(),
                b"AAAAABBBBBCCCCCAAAAABBBBB".to_vec(),
            ),
        ]);
    }
    members.sort();
    members
}

fn collect_members(root: &Path, members: &mut Vec<(String, Vec<u8>)>) {
    let entries: std::fs::ReadDir = std::fs::read_dir(root).expect("read ARC output directory");
    for entry in entries {
        let path: PathBuf = entry.expect("read ARC output entry").path();
        if path.is_dir() {
            collect_members(&path, members);
        } else if let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str)
            && name.starts_with("METHOD")
        {
            members.push((
                name.to_owned(),
                std::fs::read(path).expect("read recovered ARC member"),
            ));
        }
    }
}

fn recover_batch(jobs: u32) -> Vec<(String, Vec<u8>)> {
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-arc-fixed-input")
            .expect("create ARC batch input");
    for name in ["first.arc", "second.arc"] {
        std::fs::write(input.path().join(name), FIXTURE).expect("stage ARC fixture");
    }
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-arc-fixed-output")
            .expect("create ARC batch output");
    let process: Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("auto")
        .arg(input.path())
        .arg("--out")
        .arg(output.path())
        .arg("--jobs")
        .arg(jobs.to_string())
        .arg("--max-depth")
        .arg("3")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("spawn ARC batch auto: {error}"));
    assert!(
        process.status.success(),
        "disrobe auto failed for jobs={jobs}: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    let mut members: Vec<(String, Vec<u8>)> = Vec::new();
    collect_members(output.path(), &mut members);
    members.sort();
    members
}

#[test]
fn extract_and_auto_recover_fixed_lzw_arc_members_deterministically() {
    let fixture: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("extract-arc-fixed-input")
            .expect("create ARC input");
    let archive: PathBuf = fixture.path().join("methods.arc");
    std::fs::write(&archive, FIXTURE).expect("stage ARC fixture");
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("extract-arc-fixed-output")
            .expect("create ARC output");
    let process: Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("extract")
        .arg(&archive)
        .arg("--out")
        .arg(output.path())
        .stdin(Stdio::null())
        .output()
        .expect("run direct ARC extraction");
    assert!(
        process.status.success(),
        "disrobe extract failed: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    let mut direct: Vec<(String, Vec<u8>)> = Vec::new();
    collect_members(output.path(), &mut direct);
    direct.sort();
    assert_eq!(direct, expected_members(1));

    let serial: Vec<(String, Vec<u8>)> = recover_batch(1);
    let parallel: Vec<(String, Vec<u8>)> = recover_batch(4);
    assert_eq!(serial, parallel);
    assert_eq!(serial, expected_members(2));
}
