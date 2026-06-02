#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_ruby::{RubyAnalysis, analyze_bytes};

mod common;

fn irep_section_body() -> Vec<u8> {
    let iseq: [u8; 11] = [
        0x12, 0x01, 0x51, 0x02, 0x00, 0x2f, 0x01, 0x00, 0x01, 0x38, 0x01,
    ];
    let mut rec: Vec<u8> = Vec::new();
    rec.extend_from_slice(&0u32.to_be_bytes());
    rec.extend_from_slice(&1u16.to_be_bytes());
    rec.extend_from_slice(&3u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&(iseq.len() as u32).to_be_bytes());
    rec.extend_from_slice(&iseq);
    rec.extend_from_slice(&1u16.to_be_bytes());
    rec.push(0x00);
    rec.extend_from_slice(&5u16.to_be_bytes());
    rec.extend_from_slice(b"world\x00");
    rec.extend_from_slice(&1u16.to_be_bytes());
    rec.extend_from_slice(&5u16.to_be_bytes());
    rec.extend_from_slice(b"greet\x00");

    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&rec);
    body
}

#[test]
fn decompiles_mruby_irep_with_recovered_body_symbols_and_pool() {
    let sections: Vec<Vec<u8>> = vec![
        common::synth_section(*b"IREP", &irep_section_body()),
        common::synth_section(*b"DBG ", &[0u8; 4]),
        common::synth_section(*b"LVAR", &[0u8; 4]),
        common::synth_section(*b"END ", &[]),
    ];
    let bytes: Vec<u8> = common::synth_rite(*b"0300", &sections);
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "x.mrb").expect("analyze");
    let mrb = analysis.mruby.expect("mruby");
    assert!(mrb.decompiled.has_debug_info);
    assert!(mrb.decompiled.has_local_var_names);
    let irep = mrb.irep.expect("irep tree parsed");
    assert_eq!(irep.records.len(), 1);
    assert_eq!(irep.records[0].nregs, 3);
    assert_eq!(irep.records[0].insn_len, 11);
    assert_eq!(irep.records[0].iseq.len(), 11);
    assert!(
        mrb.decompiled
            .recovered_symbols
            .contains(&"greet".to_owned())
    );
    assert!(
        mrb.decompiled
            .recovered_strings
            .contains(&"world".to_owned())
    );
    assert!(mrb.decompiled.source.contains(":greet"));
    assert!(mrb.decompiled.source.contains("DBG section present"));
    assert!(mrb.decompiled.source.contains("LVAR section present"));
    assert!(mrb.decompiled.has_body, "should reconstruct a body");
    assert!(
        mrb.decompiled.source.contains("greet(\"world\")"),
        "expected recovered `greet(\"world\")` call, got:\n{}",
        mrb.decompiled.source
    );
}
