#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{ObfuscatorFamily, detect_obfuscators};

#[test]
fn alcatraz_runtime_marker_detected() {
    let mut buf: Vec<u8> = vec![0u8; 1024];
    buf[100..110].copy_from_slice(b"AlcatrazRT");
    let hits = detect_obfuscators(&buf);
    assert!(hits.iter().any(|h| h.family == ObfuscatorFamily::Alcatraz));
}

#[test]
#[ignore = "fixture: no ALCATRAZ-protected sample is committed; the Elastic Labs 2024 sample is not redistributable"]
fn real_alcatraz_sample_strip() {}
