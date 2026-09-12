#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_pass_ruby::{Flavor, RubyAnalysis, RubyError, YarvBinaryHeader, analyze_bytes};

mod common;

fn corpus(rel: &str) -> Vec<u8> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("ruby");
    for seg in rel.split('/') {
        p.push(seg);
    }
    std::fs::read(&p).unwrap_or_else(|_| panic!("missing committed fixture corpus/ruby/{rel}"))
}

fn header_field_le(bytes: &[u8], byte_offset: usize) -> u32 {
    let slice: [u8; 4] = bytes[byte_offset..byte_offset + 4]
        .try_into()
        .expect("header field present");
    u32::from_le_bytes(slice)
}

#[test]
fn reader_recovers_the_version_and_counts_mri_stamped_into_hello() {
    let bytes: Vec<u8> = corpus("mri/yarv/hello.rb.yarvc");
    let truth_major: u32 = header_field_le(&bytes, 4);
    let truth_minor: u32 = header_field_le(&bytes, 8);
    let truth_size: u32 = header_field_le(&bytes, 12);
    let truth_iseq_count: u32 = header_field_le(&bytes, 20);
    let truth_obj_count: u32 = header_field_le(&bytes, 24);

    let analysis: RubyAnalysis = analyze_bytes(&bytes, "hello.rb.yarvc").expect("analyze");
    assert_eq!(analysis.flavor, Flavor::YarvBinary);
    let yarv = analysis.yarv.expect("yarv present");
    let header: YarvBinaryHeader = yarv.header;

    assert_eq!((header.major, header.minor), (3, 4));
    assert_eq!((header.major, header.minor), (truth_major, truth_minor));
    assert_eq!(header.size, truth_size);
    assert_eq!(header.size as usize, bytes.len());
    assert_eq!(header.iseq_list_size, truth_iseq_count);
    assert_eq!(header.iseq_list_size, 1);
    assert_eq!(header.global_object_list_size, truth_obj_count);
    assert_eq!(header.global_object_list_size, 7);
}

#[test]
fn reader_recovers_the_multi_iseq_counts_mri_stamped_into_greeter() {
    let bytes: Vec<u8> = corpus("mri/yarv/greeter.rb.yarvc");
    let truth_iseq_count: u32 = header_field_le(&bytes, 20);
    let truth_obj_count: u32 = header_field_le(&bytes, 24);

    let analysis: RubyAnalysis = analyze_bytes(&bytes, "greeter.rb.yarvc").expect("analyze");
    let yarv = analysis.yarv.expect("yarv present");

    assert_eq!((yarv.header.major, yarv.header.minor), (3, 4));
    assert_eq!(yarv.header.iseq_list_size, truth_iseq_count);
    assert_eq!(yarv.header.iseq_list_size, 5);
    assert_eq!(yarv.header.global_object_list_size, truth_obj_count);
    assert_eq!(yarv.header.global_object_list_size, 26);
    assert_eq!(yarv.ibf.iseqs.len() as u32, truth_iseq_count);
}

#[test]
fn synthetic_header_version_gate_accepts_supported_and_rejects_future() {
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
    }
    let bytes: Vec<u8> = common::synth_yarv(4, 0, &[]);
    let err: RubyError = analyze_bytes(&bytes, "x.yarb").expect_err("unsupported");
    assert!(matches!(
        err,
        RubyError::YarvUnsupportedVersion { major: 4, minor: 0 }
    ));
}
