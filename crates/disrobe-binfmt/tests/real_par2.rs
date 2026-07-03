#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::{Par2RecoverySet, parse_par2};
use disrobe_binfmt::{ExtractionResult, extract_to};

const FORMAT_DIR: &str = "par2";
const FIXTURE_NAME: &str = "recovery.par2";

fn temp_dir(tag: &str) -> PathBuf {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-par2-{}-{tag}", std::process::id()));
    if dir.exists() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

#[test]
fn par2_identifies_protected_files_and_recovery_slices() {
    let bytes: Vec<u8> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME)
        .unwrap_or_else(|| panic!("missing fixture corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME}"));
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Par2));

    let set: Par2RecoverySet = parse_par2(&bytes).expect("parse par2");
    let want_name: String =
        String::from_utf8(common::load_fixture(FORMAT_DIR, "expected/protected-name.txt").unwrap())
            .unwrap();
    let want_len: u64 = String::from_utf8(
        common::load_fixture(FORMAT_DIR, "expected/protected-length.txt").unwrap(),
    )
    .unwrap()
    .parse()
    .unwrap();

    assert_eq!(set.protected_files.len(), 1, "one protected file expected");
    assert_eq!(set.protected_files[0].name, want_name);
    assert_eq!(set.protected_files[0].length, want_len);
    assert_eq!(set.recovery_slice_count, 1);
    assert_eq!(
        set.creator.as_deref(),
        Some("disrobe spec-real par2 generator")
    );
}

#[test]
fn par2_carves_recovery_set_and_summary() {
    let bytes: Vec<u8> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME).unwrap();
    let out: PathBuf = temp_dir("carve");
    let result: ExtractionResult =
        extract_to(ContainerKind::Par2, &bytes, &out).expect("extract par2");
    assert_eq!(result.kind, ContainerKind::Par2);
    let carved: Vec<u8> =
        std::fs::read(out.join("recovery-set.par2")).expect("carved recovery set");
    assert_eq!(
        carved, bytes,
        "carved recovery set must be the verbatim input"
    );
    assert!(out.join(".disrobe-par2.json").is_file());
}
