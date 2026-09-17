#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const FIXTURE: &[u8] = include_bytes!("../../../corpus/binfmt/arj/method4.arj");
const HELLO: &[u8] = include_bytes!("../../../corpus/binfmt/arj/expected/hello.txt");
const README: &[u8] = include_bytes!("../../../corpus/binfmt/arj/expected/readme.txt");
const NESTED: &[u8] = include_bytes!("../../../corpus/binfmt/arj/expected/sub/nested.txt");
const TIERS: &[u8] = include_bytes!("../../../corpus/binfmt/arj/expected/tiers.bin");

const TRACKED: [&str; 4] = ["hello.txt", "readme.txt", "nested.txt", "tiers.bin"];

fn expected_members(copies: usize) -> Vec<(String, Vec<u8>)> {
    let mut members: Vec<(String, Vec<u8>)> = Vec::with_capacity(copies * TRACKED.len());
    for _ in 0..copies {
        members.extend([
            ("hello.txt".to_owned(), HELLO.to_vec()),
            ("nested.txt".to_owned(), NESTED.to_vec()),
            ("readme.txt".to_owned(), README.to_vec()),
            ("tiers.bin".to_owned(), TIERS.to_vec()),
        ]);
    }
    members.sort();
    members
}

fn collect_members(root: &Path, members: &mut Vec<(String, Vec<u8>)>) {
    let entries: std::fs::ReadDir = std::fs::read_dir(root).expect("read ARJ output directory");
    for entry in entries {
        let path: PathBuf = entry.expect("read ARJ output entry").path();
        if path.is_dir() {
            collect_members(&path, members);
        } else if let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str)
            && TRACKED.contains(&name)
        {
            members.push((
                name.to_owned(),
                std::fs::read(path).expect("read recovered ARJ member"),
            ));
        }
    }
}

fn recover_batch(jobs: u32) -> Vec<(String, Vec<u8>)> {
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-arj-input")
            .expect("create ARJ batch input");
    for name in ["first.arj", "second.arj"] {
        std::fs::write(input.path().join(name), FIXTURE).expect("stage ARJ fixture");
    }
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-arj-output")
            .expect("create ARJ batch output");
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
        .unwrap_or_else(|error: std::io::Error| panic!("spawn ARJ batch auto: {error}"));
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
fn extract_and_auto_recover_real_arj_method4_members_deterministically() {
    let fixture: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("extract-arj-input").expect("create ARJ input");
    let archive: PathBuf = fixture.path().join("method4.arj");
    std::fs::write(&archive, FIXTURE).expect("stage ARJ fixture");
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("extract-arj-output").expect("create ARJ output");
    let process: Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("extract")
        .arg(&archive)
        .arg("--out")
        .arg(output.path())
        .stdin(Stdio::null())
        .output()
        .expect("run direct ARJ extraction");
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
    assert_eq!(
        serial, parallel,
        "ARJ automatic recovery must not depend on the worker count"
    );
    assert_eq!(serial, expected_members(2));
}
