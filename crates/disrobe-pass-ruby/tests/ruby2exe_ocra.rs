#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_ruby::{Flavor, RubyAnalysis, WrapperKind, analyze_bytes};

mod common;

#[test]
fn extracts_ruby2exe_payload_offset_and_length() {
    let mut bytes: Vec<u8> = b"MZ".to_vec();
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.extend_from_slice(b"Ruby2Exe");
    bytes.extend_from_slice(b"embedded-script-bytes");
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "wrapped.exe").expect("analyze");
    assert_eq!(analysis.flavor, Flavor::Ruby2Exe);
    let w = analysis.wrapper.expect("wrapper");
    assert_eq!(w.kind, WrapperKind::Ruby2Exe);
    assert_eq!(w.embedded_payload_len, 21);
    assert_eq!(w.container_format, "pe");
}

#[test]
fn extracts_ocra_payload_offset_and_length() {
    let mut bytes: Vec<u8> = b"MZ".to_vec();
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.extend_from_slice(b"OcraStub");
    bytes.extend_from_slice(b"payload-blob");
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "wrapped.exe").expect("analyze");
    assert_eq!(analysis.flavor, Flavor::Ocra);
    let w = analysis.wrapper.expect("wrapper");
    assert_eq!(w.kind, WrapperKind::Ocra);
    assert_eq!(w.embedded_payload_len, 12);
}
