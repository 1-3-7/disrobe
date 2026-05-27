#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use disrobe_binfmt::containers::cramfs::{CRAMFS_MAGIC, CramfsHeader, detect_cramfs};

const FORMAT_DIR: &str = "cramfs";
const FIXTURE_NAME: &str = "hello.cramfs";

#[test]
fn real_cramfs_header_parsed() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME) else {
        panic!(
            "missing fixture: corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME} — see corpus/binfmt/MANIFEST.toml for regeneration"
        );
    };
    assert!(bytes.len() > 1_000_000);
    let header: CramfsHeader = detect_cramfs(&bytes).expect("detect cramfs");
    assert_eq!(header.magic, CRAMFS_MAGIC);
    assert!(
        header.size as usize <= bytes.len(),
        "cramfs size field {} > file size {}",
        header.size,
        bytes.len()
    );
}
