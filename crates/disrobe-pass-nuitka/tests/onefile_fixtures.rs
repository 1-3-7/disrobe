#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

//! Tests against checked-in artifacts derived from a real Nuitka 4.1.1 `--onefile` payload with truncated file bodies.

use std::path::{Path, PathBuf};

use disrobe_pass_nuitka::{FilenameEncoding, OnefilePayload, extract_onefile};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// The seven files a real Windows `--onefile` hello build embeds, in payload order. These
/// names were observed in the genuine binary, not invented.
const REAL_ENTRY_NAMES: [&str; 7] = [
    "hello.dll",
    "_wmi.pyd",
    "_zstd.pyd",
    "python314.dll",
    "unicodedata.pyd",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
];

#[test]
fn real_onefile_header_slice_walks_and_names_match() {
    let bytes: Vec<u8> = std::fs::read(fixture("onefile_header_slice.kax"))
        .expect("checked-in real onefile header slice");
    let payload: OnefilePayload = extract_onefile(&bytes, 0).expect("walk real-format KAX slice");

    assert_eq!(payload.encoding, FilenameEncoding::Utf16Le);
    assert!(
        !payload.has_checksums,
        "default --onefile has no per-entry CRC"
    );
    assert!(!payload.compressed);

    let names: Vec<&str> = payload
        .entries
        .iter()
        .map(|e| e.filename.as_str())
        .collect();
    assert_eq!(
        names, REAL_ENTRY_NAMES,
        "recovered real filenames must match"
    );

    for entry in &payload.entries {
        assert!(
            entry.data.starts_with(b"MZ"),
            "{} body should start with MZ",
            entry.filename
        );
        assert_eq!(entry.data.len() as u64, entry.size);
    }
}

#[test]
fn planted_marker_fixture_is_present_for_regen_assertions() {
    let marker: String =
        std::fs::read_to_string(fixture("planted_marker.txt")).expect("planted marker");
    assert!(
        marker.starts_with("DISROBE_NUITKA_FIXTURE_MARKER_"),
        "marker = {marker:?}"
    );
}
