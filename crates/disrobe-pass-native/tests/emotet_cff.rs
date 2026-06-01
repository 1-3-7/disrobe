#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{ObfuscatorFamily, detect_obfuscators, undo_emotet_cff_stub};

#[test]
fn emotet_cff_marker_detected() {
    let mut buf: Vec<u8> = vec![0u8; 64];
    buf[0..6].copy_from_slice(b"EmoCFF");
    let hits = detect_obfuscators(&buf);
    assert!(hits.iter().any(|h| h.family == ObfuscatorFamily::EmotetCff));
}

#[test]
fn emotet_stub_returns_zero_until_fixture_lands() {
    assert_eq!(undo_emotet_cff_stub().expect("stub"), 0);
}

#[test]
#[ignore = "FIXTURE PENDING: real Emotet sample required (malware family - sandbox-only)"]
fn real_emotet_sample_strip() {}
