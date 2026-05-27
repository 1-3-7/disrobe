#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_ruby::{Flavor, RubyAnalysis, analyze_bytes};

mod common;

#[test]
fn walks_truffleruby_aot_elf_image() {
    let mut bytes: Vec<u8> = b"\x7FELF".to_vec();
    bytes.extend_from_slice(&[0u8; 128]);
    bytes.extend_from_slice(b"TruffleRuby-NativeImage");
    bytes.extend_from_slice(&[0u8; 64]);
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "truffleruby").expect("analyze");
    assert_eq!(analysis.flavor, Flavor::TruffleRubyAot);
    let t = analysis.truffleruby.expect("truffleruby");
    assert_eq!(t.container_format, "elf");
    assert!(t.marker_offset > 4);
}
