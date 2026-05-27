#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use disrobe_binfmt::containers::ext4::{EXT4_MAGIC, Ext4SuperblockSummary, detect_ext4};

const FORMAT_DIR: &str = "ext4";
const FIXTURE_NAME: &str = "hello.ext4";

#[test]
fn real_ext4_superblock_parsed() {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME) else {
        panic!(
            "missing fixture: corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME} — see corpus/binfmt/MANIFEST.toml for regeneration"
        );
    };
    assert_eq!(bytes.len(), 16 * 1024 * 1024, "fixture should be 16 MiB");
    let sb: Ext4SuperblockSummary = detect_ext4(&bytes).expect("ext4 superblock");
    assert_eq!(sb.magic, EXT4_MAGIC);
    assert_eq!(sb.inodes_count, 4096);
    assert!(sb.blocks_count_lo > 0);
}
