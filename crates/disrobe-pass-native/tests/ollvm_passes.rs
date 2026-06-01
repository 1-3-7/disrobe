#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{
    ObfuscatorFamily, detect_obfuscators, strip_ollvm_bcf_stub, undo_ollvm_substitution_stub,
    unflatten_ollvm_stub,
};

#[test]
fn ollvm_cff_marker_detected() {
    let mut buf: Vec<u8> = vec![0u8; 64];
    buf[0..10].copy_from_slice(b"switch_var");
    let hits = detect_obfuscators(&buf);
    assert!(
        hits.iter()
            .any(|h| h.family == ObfuscatorFamily::OllvmFlattening)
    );
}

#[test]
fn ollvm_bcf_stub_returns_zero_until_fixture_lands() {
    let n: u32 = strip_ollvm_bcf_stub().expect("bcf stub");
    assert_eq!(n, 0);
}

#[test]
fn ollvm_substitution_stub_returns_zero_until_fixture_lands() {
    let n: u32 = undo_ollvm_substitution_stub().expect("sub stub");
    assert_eq!(n, 0);
}

#[test]
fn ollvm_unflatten_stub_describes_pending_state() {
    let report = unflatten_ollvm_stub().expect("cff stub");
    assert_eq!(report.recovered_blocks, 0);
    assert!(
        report
            .notes
            .first()
            .is_some_and(|n: &String| n.contains("FIXTURE PENDING"))
    );
}

#[test]
#[ignore = "FIXTURE PENDING: real OLLVM-flattened binary required"]
fn real_ollvm_cff_unflatten_round_trip() {}
