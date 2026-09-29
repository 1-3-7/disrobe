#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{ObfuscatorFamily, detect_obfuscators};

#[test]
fn emotet_cff_marker_detected() {
    let mut buf: Vec<u8> = vec![0u8; 64];
    buf[0..6].copy_from_slice(b"EmoCFF");
    let hits = detect_obfuscators(&buf);
    assert!(hits.iter().any(|h| h.family == ObfuscatorFamily::EmotetCff));
}

#[test]
#[ignore = "fixture: no Emotet sample is committed, because it is a live malware family and this project never executes one; the same cmp-chain unflattener is graded on committed input in ollvm_passes.rs"]
fn real_emotet_sample_strip() {}
