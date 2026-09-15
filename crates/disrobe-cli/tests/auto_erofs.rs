#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const FIXTURE: &[u8] =
    include_bytes!("../../disrobe-binfmt/tests/fixtures/erofs/lzma-compact-mixed.erofs");

fn collect_payloads(root: &Path, payloads: &mut Vec<Vec<u8>>) {
    let entries: std::fs::ReadDir = std::fs::read_dir(root).expect("read EROFS output directory");
    for entry in entries {
        let path: PathBuf = entry.expect("read EROFS output entry").path();
        if path.is_dir() {
            collect_payloads(&path, payloads);
        } else if path.file_name().is_some_and(|name| name == "payload.txt") {
            payloads.push(std::fs::read(path).expect("read recovered EROFS payload"));
        }
    }
}

fn recover_batch(jobs: u32) -> Vec<Vec<u8>> {
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-erofs-input")
            .expect("create EROFS input directory");
    for name in ["first.erofs", "second.erofs"] {
        std::fs::write(input.path().join(name), FIXTURE).expect("stage EROFS fixture");
    }
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-erofs-output")
            .expect("create EROFS output directory");
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
        .unwrap_or_else(|error: std::io::Error| panic!("spawn EROFS auto: {error}"));
    assert!(
        process.status.success(),
        "disrobe auto failed for jobs={jobs}: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    collect_payloads(output.path(), &mut payloads);
    payloads.sort();
    payloads
}

#[test]
fn extract_and_auto_recover_compact_erofs_members_deterministically() {
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("extract-erofs-input")
            .expect("create EROFS input directory");
    let image: PathBuf = input.path().join("mixed.erofs");
    std::fs::write(&image, FIXTURE).expect("stage EROFS image");
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("extract-erofs-output")
            .expect("create EROFS output directory");
    let process: Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("extract")
        .arg(&image)
        .arg("--out")
        .arg(output.path())
        .stdin(Stdio::null())
        .output()
        .expect("run direct EROFS extraction");
    assert!(
        process.status.success(),
        "disrobe extract failed: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    let expected: Vec<u8> =
        std::fs::read(output.path().join("payload.txt")).expect("read direct EROFS payload");
    assert_eq!(expected.len(), 212_250);

    let serial: Vec<Vec<u8>> = recover_batch(1);
    let parallel: Vec<Vec<u8>> = recover_batch(4);
    assert_eq!(serial, parallel);
    assert_eq!(serial, vec![expected.clone(), expected]);
}
