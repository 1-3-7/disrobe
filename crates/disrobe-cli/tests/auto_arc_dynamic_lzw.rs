#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const METHOD8: &[u8] = include_bytes!("../../../corpus/binfmt/arc/method8-rle.arc");
const METHOD9: &[u8] = include_bytes!("../../../corpus/binfmt/arc/method9.arc");
const DREAM_ALONE: &[u8] = include_bytes!("../../../corpus/binfmt/arc/expected/DreamAlone");
const CRYSTALS: &[u8] = include_bytes!("../../../corpus/binfmt/arc/expected/crystals.669");

fn collect_members(root: &Path, members: &mut Vec<(String, Vec<u8>)>) {
    let entries: std::fs::ReadDir = std::fs::read_dir(root).expect("read ARC output directory");
    for entry in entries {
        let path: PathBuf = entry.expect("read ARC output entry").path();
        if path.is_dir() {
            collect_members(&path, members);
        } else if let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str)
            && matches!(name, "DreamAlone" | "crystals.669")
        {
            members.push((
                name.to_owned(),
                std::fs::read(path).expect("read recovered ARC member"),
            ));
        }
    }
}

fn expected_members() -> Vec<(String, Vec<u8>)> {
    vec![
        ("DreamAlone".to_owned(), DREAM_ALONE.to_vec()),
        ("crystals.669".to_owned(), CRYSTALS.to_vec()),
    ]
}

fn recover_batch(jobs: u32) -> Vec<(String, Vec<u8>)> {
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-arc-dynamic-input")
            .expect("create ARC batch input");
    std::fs::write(input.path().join("method8.arc"), METHOD8).expect("stage method 8 fixture");
    std::fs::write(input.path().join("method9.arc"), METHOD9).expect("stage method 9 fixture");
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-arc-dynamic-output")
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
fn extract_and_auto_recover_dynamic_lzw_arc_members_deterministically() {
    let mut direct: Vec<(String, Vec<u8>)> = Vec::new();
    for (name, fixture) in [("method8.arc", METHOD8), ("method9.arc", METHOD9)] {
        let input: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("extract-arc-dynamic-input")
                .expect("create ARC input");
        let archive: PathBuf = input.path().join(name);
        std::fs::write(&archive, fixture).expect("stage ARC fixture");
        let output: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("extract-arc-dynamic-output")
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
        collect_members(output.path(), &mut direct);
    }
    direct.sort();

    let serial: Vec<(String, Vec<u8>)> = recover_batch(1);
    let parallel: Vec<(String, Vec<u8>)> = recover_batch(4);
    assert_eq!(direct, expected_members());
    assert_eq!(serial, direct);
    assert_eq!(parallel, serial);
}
