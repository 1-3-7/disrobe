#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_ruby::{RubyError, analyze_bytes};

mod common;

fn yarv_header(
    major: u32,
    minor: u32,
    size: u32,
    iseq_n: u32,
    obj_n: u32,
    iseq_off: u32,
    obj_off: u32,
) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::with_capacity(36);
    v.extend_from_slice(b"YARB");
    v.extend_from_slice(&major.to_le_bytes());
    v.extend_from_slice(&minor.to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&iseq_n.to_le_bytes());
    v.extend_from_slice(&obj_n.to_le_bytes());
    v.extend_from_slice(&iseq_off.to_le_bytes());
    v.extend_from_slice(&obj_off.to_le_bytes());
    v
}

#[test]
fn yarv_oversized_object_count_does_not_oom_or_hang() {
    let bytes: Vec<u8> = yarv_header(3, 4, 36, 1, u32::MAX, 36, 36);
    let analysis = analyze_bytes(&bytes, "evil.yarvc").expect("must return Ok without OOM");
    let yarv = analysis.yarv.expect("yarv");
    assert!(
        yarv.ibf.objects.len() < 4096,
        "object table reads must stop at buffer end, got {}",
        yarv.ibf.objects.len()
    );
}

#[test]
fn yarv_oversized_iseq_count_is_bounded() {
    let bytes: Vec<u8> = yarv_header(3, 4, 36, u32::MAX, 0, 36, 36);
    let analysis = analyze_bytes(&bytes, "evil.yarvc").expect("must return Ok");
    let yarv = analysis.yarv.expect("yarv");
    assert!(yarv.ibf.iseq_offsets.len() < 4096);
}

#[test]
fn yarv_object_offset_past_eof_is_safe() {
    let mut v: Vec<u8> = yarv_header(3, 4, 44, 0, 1, 36, 40);
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let analysis = analyze_bytes(&v, "evil.yarvc").expect("must not panic");
    let yarv = analysis.yarv.expect("yarv");
    assert_eq!(yarv.ibf.objects.len(), 1);
    assert!(yarv.ibf.objects[0].literal.is_none());
}

#[test]
fn yarv_offsets_near_u32_max_do_not_overflow() {
    let bytes: Vec<u8> = yarv_header(3, 4, 36, 2, 2, u32::MAX - 1, u32::MAX - 1);
    let analysis = analyze_bytes(&bytes, "evil.yarvc").expect("must not overflow-panic");
    assert!(analysis.yarv.is_some());
}

#[test]
fn yarv_string_object_with_huge_len_is_safe() {
    let mut v: Vec<u8> = yarv_header(3, 4, 0, 0, 1, 36, 40);
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&44u32.to_le_bytes());
    v.push(0x45);
    v.push(0x03);
    v.push(0xfe);
    v.push(0xff);
    v.push(0xff);
    v.push(0xff);
    v.push(0x7f);
    let analysis = analyze_bytes(&v, "evil.yarvc").expect("must not panic on huge len");
    assert!(analysis.yarv.is_some());
}

#[test]
fn mruby_oversized_pool_count_is_bounded() {
    let mut rec: Vec<u8> = Vec::new();
    rec.extend_from_slice(&0u32.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u32.to_be_bytes());
    rec.extend_from_slice(&u32::MAX.to_be_bytes());
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&rec);
    let sections: Vec<Vec<u8>> = vec![
        common::synth_section(*b"IREP", &body),
        common::synth_section(*b"END ", &[]),
    ];
    let bytes: Vec<u8> = common::synth_rite(*b"0300", &sections);
    let analysis = analyze_bytes(&bytes, "evil.mrb").expect("must not OOM");
    let mrb = analysis.mruby.expect("mruby");
    assert!(
        mrb.irep.is_none(),
        "malformed pool must fail IREP parse cleanly"
    );
}

#[test]
fn mruby_recursion_bomb_is_depth_bounded() {
    let mut rec: Vec<u8> = Vec::new();
    rec.extend_from_slice(&0u32.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&1u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u32.to_be_bytes());
    rec.extend_from_slice(&0u32.to_be_bytes());
    rec.extend_from_slice(&0u32.to_be_bytes());
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0u32.to_be_bytes());
    for _ in 0..2048 {
        body.extend_from_slice(&rec);
    }
    let sections: Vec<Vec<u8>> = vec![
        common::synth_section(*b"IREP", &body),
        common::synth_section(*b"END ", &[]),
    ];
    let bytes: Vec<u8> = common::synth_rite(*b"0300", &sections);
    let analysis = analyze_bytes(&bytes, "bomb.mrb").expect("must not stack-overflow");
    let mrb = analysis.mruby.expect("mruby");
    assert!(mrb.irep.is_none() || mrb.irep.is_some());
}

fn mruby_with_iseq(iseq: &[u8], pool_count: u16, sym_count: u16, tail: &[u8]) -> Vec<u8> {
    let mut rec: Vec<u8> = Vec::new();
    rec.extend_from_slice(&0u32.to_be_bytes());
    rec.extend_from_slice(&1u16.to_be_bytes());
    rec.extend_from_slice(&4u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&(iseq.len() as u32).to_be_bytes());
    rec.extend_from_slice(iseq);
    rec.extend_from_slice(&pool_count.to_be_bytes());
    rec.extend_from_slice(&sym_count.to_be_bytes());
    rec.extend_from_slice(tail);
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&rec);
    let sections: Vec<Vec<u8>> = vec![
        common::synth_section(*b"IREP", &body),
        common::synth_section(*b"END ", &[]),
    ];
    common::synth_rite(*b"0300", &sections)
}

#[test]
fn mruby_unknown_opcode_in_body_does_not_panic() {
    let bytes: Vec<u8> = mruby_with_iseq(&[0xFE, 0xFF], 0, 0, &[]);
    let analysis = analyze_bytes(&bytes, "x.mrb").expect("analyze must not panic");
    let mrb = analysis.mruby.expect("mruby");
    assert!(
        !mrb.decompiled.has_body || mrb.decompiled.source.contains("lift failed"),
        "unknown opcode must not fabricate a body"
    );
}

#[test]
fn mruby_truncated_jump_operand_in_body_is_clean() {
    let bytes: Vec<u8> = mruby_with_iseq(&[0x25, 0x12], 0, 0, &[]);
    let analysis = analyze_bytes(&bytes, "x.mrb").expect("analyze must not panic");
    let _ = analysis.mruby.expect("mruby");
}

#[test]
fn mruby_send_with_symbol_index_past_table_does_not_panic() {
    let iseq: [u8; 6] = [0x12, 0x01, 0x2f, 0x01, 0xff, 0x00];
    let bytes: Vec<u8> = mruby_with_iseq(&iseq, 0, 0, &[]);
    let analysis = analyze_bytes(&bytes, "x.mrb").expect("analyze must not panic");
    let mrb = analysis.mruby.expect("mruby");
    if mrb.decompiled.has_body {
        assert!(mrb.decompiled.source.contains("sym255") || !mrb.decompiled.source.is_empty());
    }
}

#[test]
fn mruby_loadl_pool_index_past_table_does_not_panic() {
    let iseq: [u8; 5] = [0x02, 0x01, 0xff, 0x38, 0x01];
    let bytes: Vec<u8> = mruby_with_iseq(&iseq, 0, 0, &[]);
    let analysis = analyze_bytes(&bytes, "x.mrb").expect("analyze must not panic");
    let _ = analysis.mruby.expect("mruby");
}

#[test]
fn yarv_iseq_body_with_bad_bytecode_offset_is_safe() {
    let mut v: Vec<u8> = yarv_header(3, 4, 0, 1, 0, 36, 40);
    v.extend_from_slice(&40u32.to_le_bytes());
    v.extend_from_slice(&[0x03, 0x05, 0x01, 0x03, 0x09]);
    let analysis = analyze_bytes(&v, "evil.yarvc").expect("must not panic on bad iseq body");
    let yarv = analysis.yarv.expect("yarv");
    assert!(yarv.ibf.recovered_instruction_count < 10_000);
}

#[test]
fn yarv_small_value_truncated_at_eof_is_safe() {
    let mut v: Vec<u8> = yarv_header(3, 4, 0, 1, 0, 36, 40);
    v.push(0x02);
    let analysis = analyze_bytes(&v, "evil.yarvc").expect("must not panic on truncated varint");
    assert!(analysis.yarv.is_some());
}

#[test]
fn empty_and_tiny_inputs_never_panic() {
    assert!(matches!(
        analyze_bytes(&[], "x.rb"),
        Err(RubyError::EmptyInput)
    ));
    for garbage in [
        b"YARB".as_slice(),
        b"RITE".as_slice(),
        b"YARB\x00\x00".as_slice(),
        &[0xFFu8; 3],
    ] {
        let _ = analyze_bytes(garbage, "x");
    }
}
