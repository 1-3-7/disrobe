#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_ruby::{RubyAnalysis, analyze_bytes};

mod common;

#[test]
fn emits_instructionsequence_disasm_parity_text() {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&[0x00u8]);
    body.push(0x0Du8);
    body.push(0x2Eu8);
    let bytes: Vec<u8> = common::synth_yarv(3, 2, &body);
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "x.yarb").expect("analyze");
    let yarv = analysis.yarv.expect("yarv present");
    assert!(yarv.disasm_text.contains("== disasm: <top> (ruby 3.2) =="));
    assert!(yarv.disasm_text.contains("nop"));
    assert!(yarv.disasm_text.contains("putnil"));
    assert!(yarv.disasm_text.contains("leave"));
}
