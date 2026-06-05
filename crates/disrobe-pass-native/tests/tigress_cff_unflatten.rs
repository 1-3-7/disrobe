#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{ObfuscatorFamily, detect_obfuscators, unflatten_tigress_stub};

#[test]
fn tigress_cff_marker_detected() {
    let mut buf: Vec<u8> = vec![0u8; 64];
    buf[0..16].copy_from_slice(b"_TIGRESS_flatten");
    let hits = detect_obfuscators(&buf);
    assert!(
        hits.iter()
            .any(|h| h.family == ObfuscatorFamily::TigressCff)
    );
}

#[test]
fn tigress_unflatten_stub_returns_pending_state() {
    let report = unflatten_tigress_stub().expect("tigress stub");
    assert_eq!(report.recovered_blocks, 0);
}

#[test]
#[ignore = "FIXTURE PENDING: real Tigress-flattened binary required"]
fn real_tigress_sample_unflatten() {}
