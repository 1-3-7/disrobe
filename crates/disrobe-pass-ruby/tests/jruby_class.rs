#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_ruby::{Flavor, RubyAnalysis, analyze_bytes};

mod common;

#[test]
fn delegates_jruby_class_to_jvm_pass() {
    let mut bytes: Vec<u8> = b"\xCA\xFE\xBA\xBE".to_vec();
    bytes.extend_from_slice(&[0u8, 0u8, 0u8, 0x34u8]);
    bytes.extend_from_slice(&[0u8; 24]);
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "Greeter.class").expect("analyze");
    assert_eq!(analysis.flavor, Flavor::JrubyClass);
    let d = analysis.jruby.expect("jruby");
    assert_eq!(d.delegate_pass, "disrobe-pass-jvm");
    assert_eq!(d.major, 0x34);
}
