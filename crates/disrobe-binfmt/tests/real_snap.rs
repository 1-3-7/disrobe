#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use disrobe_binfmt::containers::snap::detect_snap;
use disrobe_binfmt::containers::squashfs::{SquashfsCompression, SquashfsSuperblock};

const FORMAT_DIR: &str = "snap";
const FIXTURE_NAME: &str = "hello.snap";

#[test]
fn real_snap_detected_as_squashfs_at_offset_zero() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME) else {
        panic!(
            "missing fixture: corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME} — see corpus/binfmt/MANIFEST.toml for regeneration"
        );
    };
    assert!(bytes.len() > 1_000_000);
    let sb: SquashfsSuperblock = detect_snap(&bytes).expect("snap detection");
    assert_eq!(sb.version_major, 4);
    assert!(matches!(sb.compression, SquashfsCompression::Xz));
}
