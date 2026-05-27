#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use disrobe_binfmt::containers::msi::{MsiSummary, parse_msi_minimal};

const FORMAT_DIR: &str = "msi";
const FIXTURE_NAME: &str = "hello.msi";

#[test]
fn real_msi_summary_round_trip() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME) else {
        panic!(
            "missing fixture: corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME} — see corpus/binfmt/MANIFEST.toml for regeneration (requires WiX)"
        );
    };
    assert!(
        bytes.len() > 1_000_000,
        "msi fixture too small: {}",
        bytes.len()
    );
    let summary: MsiSummary = parse_msi_minimal(&bytes).expect("parse real msi");
    assert!(!summary.tables.is_empty(), "msi tables empty");
    let table_set: std::collections::BTreeSet<&str> =
        summary.tables.iter().map(String::as_str).collect();
    for required in ["File", "Component", "Feature", "Directory", "Media"] {
        assert!(
            table_set.contains(required),
            "missing required msi table `{required}` (have {table_set:?})"
        );
    }
    let stream_set: std::collections::BTreeSet<&str> =
        summary.streams.iter().map(String::as_str).collect();
    let has_cab: bool = stream_set
        .iter()
        .any(|s: &&str| s.to_ascii_lowercase().contains("cab"));
    assert!(
        has_cab,
        "expected embedded cab stream in msi (streams: {stream_set:?})"
    );
}
