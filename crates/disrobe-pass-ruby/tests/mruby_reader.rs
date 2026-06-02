#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_ruby::{Flavor, RubyAnalysis, RubyError, analyze_bytes};

mod common;

#[test]
fn reads_mrb_across_format_versions() {
    for fmt in [*b"0001", *b"0002", *b"0003", *b"0030", *b"0200", *b"0300"] {
        let sections: Vec<Vec<u8>> = vec![
            common::synth_section(*b"IREP", &[0u8; 16]),
            common::synth_section(*b"END ", &[]),
        ];
        let bytes: Vec<u8> = common::synth_rite(fmt, &sections);
        let analysis: RubyAnalysis = analyze_bytes(&bytes, "tiny.mrb").expect("analyze");
        assert_eq!(analysis.flavor, Flavor::MrubyBinary);
        let mrb = analysis.mruby.expect("mruby");
        assert_eq!(mrb.binary.irep_count, 1);
        assert!(!mrb.binary.has_debug);
    }
}

#[test]
fn rejects_unknown_section_id() {
    let sections: Vec<Vec<u8>> = vec![common::synth_section(*b"WUT?", &[0u8; 4])];
    let bytes: Vec<u8> = common::synth_rite(*b"0300", &sections);
    let err: RubyError = analyze_bytes(&bytes, "x.mrb").expect_err("unknown");
    assert!(matches!(err, RubyError::MrubyUnknownSection { .. }));
}
