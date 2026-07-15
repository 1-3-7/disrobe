use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_dart::{DartBlobKind, SnapshotBlob, locate_snapshot_blobs};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn real_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("flutter_3_44_6")
        .join("receipt_validator_arm64.so")
}

#[test]
fn locates_all_four_snapshot_symbols_in_real_elf() -> TestResult {
    let bytes: Vec<u8> = std::fs::read(real_fixture())?;
    let blobs: BTreeMap<DartBlobKind, SnapshotBlob<'_>> = locate_snapshot_blobs(&bytes)?;
    assert_eq!(blobs.len(), 4);
    assert!(blobs.contains_key(&DartBlobKind::VmData));
    assert!(blobs.contains_key(&DartBlobKind::VmInstructions));
    assert!(blobs.contains_key(&DartBlobKind::IsolateData));
    assert!(blobs.contains_key(&DartBlobKind::IsolateInstructions));
    assert!(blobs[&DartBlobKind::VmData].bytes.len() > 16_000);
    assert!(blobs[&DartBlobKind::IsolateData].bytes.len() > 800_000);
    Ok(())
}
