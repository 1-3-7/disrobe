#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_ruby::{Fidelity, RubyAnalysis, analyze_bytes};

mod common;

#[test]
fn decompiles_return_one_plus_two_to_ruby_surface() {
    let mut body: Vec<u8> = Vec::new();
    body.push(0x0Fu8);
    body.extend_from_slice(&1u32.to_le_bytes());
    body.push(0x0Fu8);
    body.extend_from_slice(&2u32.to_le_bytes());
    body.push(0x38u8);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.push(0x2Eu8);
    let bytes: Vec<u8> = common::synth_yarv(3, 2, &body);
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "x.yarb").expect("analyze");
    let yarv = analysis.yarv.expect("yarv");
    assert_eq!(yarv.decompiled.fidelity, Fidelity::Lossy);
    assert!(yarv.decompiled.source.contains("return (OBJ#1 + OBJ#2)"));
    assert!(yarv.decompiled.statement_count >= 1);
}

#[test]
fn decompiles_setlocal_assignment() {
    let mut body: Vec<u8> = Vec::new();
    body.push(0x0Fu8);
    body.extend_from_slice(&42u32.to_le_bytes());
    body.push(0x02u8);
    body.extend_from_slice(&3u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.push(0x2Eu8);
    let bytes: Vec<u8> = common::synth_yarv(3, 2, &body);
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "x.yarb").expect("analyze");
    let yarv = analysis.yarv.expect("yarv");
    assert!(yarv.decompiled.source.contains("local_3 = OBJ#42"));
}
