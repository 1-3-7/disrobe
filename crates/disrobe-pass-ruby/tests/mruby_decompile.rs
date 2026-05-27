#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_ruby::{RubyAnalysis, analyze_bytes};

mod common;

#[test]
fn decompiles_mruby_structure_with_debug_and_lvar() {
    let sections: Vec<Vec<u8>> = vec![
        common::synth_section(*b"IREP", &[0u8; 16]),
        common::synth_section(*b"IREP", &[0u8; 8]),
        common::synth_section(*b"DBG ", &[0u8; 4]),
        common::synth_section(*b"LVAR", &[0u8; 4]),
        common::synth_section(*b"END ", &[]),
    ];
    let bytes: Vec<u8> = common::synth_rite(*b"0300", &sections);
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "x.mrb").expect("analyze");
    let mrb = analysis.mruby.expect("mruby");
    assert_eq!(mrb.binary.irep_count, 2);
    assert!(mrb.decompiled.has_debug_info);
    assert!(mrb.decompiled.has_local_var_names);
    assert!(mrb.decompiled.source.contains("__irep_0"));
    assert!(mrb.decompiled.source.contains("__irep_1"));
    assert!(mrb.decompiled.source.contains("DBG section present"));
    assert!(mrb.decompiled.source.contains("LVAR section present"));
}
