#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use disrobe_binfmt::containers::nsis::{NsisHeader, detect_nsis};

const FORMAT_DIR: &str = "nsis";
const FIXTURE_NAME: &str = "hello.exe";
const GRADED: &str = "the real NSIS header detection";

#[test]
fn real_nsis_first_header_detected_in_pe_tail() {
    let Some(bytes): Option<Vec<u8>> =
        common::requirement::regenerable_fixture(FORMAT_DIR, FIXTURE_NAME, GRADED)
    else {
        return;
    };
    assert!(
        bytes.len() > 1_000_000,
        "nsis fixture too small: {}",
        bytes.len()
    );
    assert_eq!(&bytes[0..2], b"MZ", "expected PE/MZ prefix");
    let header: NsisHeader = detect_nsis(&bytes).expect("nsis first-header");
    assert!(header.offset > 0);
    assert!(header.header_size > 0);
    assert!(
        u64::from(header.archive_size) <= bytes.len() as u64,
        "archive_size {} > file size {}",
        header.archive_size,
        bytes.len()
    );
}
