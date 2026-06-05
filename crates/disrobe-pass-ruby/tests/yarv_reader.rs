#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_ruby::{Flavor, RubyAnalysis, RubyError, YarvBinaryHeader, analyze_bytes};

mod common;

#[test]
fn reads_synthetic_yarv_header_for_supported_versions() {
    for (major, minor) in [
        (2u32, 6u32),
        (2u32, 7u32),
        (3u32, 0u32),
        (3u32, 1u32),
        (3u32, 2u32),
        (3u32, 3u32),
        (3u32, 4u32),
    ] {
        let body: Vec<u8> = vec![0x00u8, 0x2Eu8];
        let bytes: Vec<u8> = common::synth_yarv(major, minor, &body);
        let analysis: RubyAnalysis =
            analyze_bytes(&bytes, &format!("x_{major}_{minor}.yarb")).expect("analyze");
        assert_eq!(analysis.flavor, Flavor::YarvBinary);
        let yarv = analysis.yarv.expect("yarv present");
        let header: YarvBinaryHeader = yarv.header;
        assert_eq!(header.major, major);
        assert_eq!(header.minor, minor);
    }
}

#[test]
fn rejects_unsupported_yarv_version() {
    let bytes: Vec<u8> = common::synth_yarv(4, 0, &[]);
    let err: RubyError = analyze_bytes(&bytes, "x.yarb").expect_err("unsupported");
    assert!(matches!(
        err,
        RubyError::YarvUnsupportedVersion { major: 4, minor: 0 }
    ));
}
