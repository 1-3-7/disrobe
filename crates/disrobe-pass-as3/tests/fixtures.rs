#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]

use disrobe_pass_as3::abc::{ABC_MAJOR, ABC_MINOR};
use disrobe_pass_as3::swf::{
    Swf, SwfCompression, TagCode, parse, parse_define_sprite, parse_do_abc,
};

fn rect_zero_bytes() -> Vec<u8> {
    vec![0x00]
}

fn pack_short_tag(code: u16, payload: &[u8]) -> Vec<u8> {
    let len: u16 = payload.len() as u16;
    let header: u16 = (code << 6) | (len & 0x3F);
    let mut out: Vec<u8> = Vec::new();
    if payload.len() < 0x3F {
        out.extend_from_slice(&header.to_le_bytes());
    } else {
        let long_header: u16 = (code << 6) | 0x3F;
        out.extend_from_slice(&long_header.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    }
    out.extend_from_slice(payload);
    out
}

fn build_swf(body_inner: &[u8]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&rect_zero_bytes());
    body.extend_from_slice(&24_u16.to_le_bytes());
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(body_inner);
    body.extend_from_slice(&pack_short_tag(TagCode::END.0, &[]));

    let mut swf: Vec<u8> = Vec::new();
    swf.extend_from_slice(b"FWS");
    swf.push(10);
    let file_length: u32 = (8 + body.len()) as u32;
    swf.extend_from_slice(&file_length.to_le_bytes());
    swf.extend_from_slice(&body);
    swf
}

fn build_minimal_abc_blob() -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&ABC_MINOR.to_le_bytes());
    b.extend_from_slice(&ABC_MAJOR.to_le_bytes());
    b.extend(std::iter::repeat_n(0x01u8, 7));
    b.extend(std::iter::repeat_n(0x00u8, 5));
    b
}

#[test]
fn fixture_a_swf_with_define_sprite() {
    let sprite_payload: Vec<u8> = {
        let mut p: Vec<u8> = Vec::new();
        p.extend_from_slice(&42_u16.to_le_bytes());
        p.extend_from_slice(&3_u16.to_le_bytes());
        p.extend_from_slice(&pack_short_tag(TagCode::SHOW_FRAME.0, &[]));
        p.extend_from_slice(&pack_short_tag(TagCode::END.0, &[]));
        p
    };
    let body_inner: Vec<u8> = pack_short_tag(TagCode::DEFINE_SPRITE.0, &sprite_payload);
    let bytes: Vec<u8> = build_swf(&body_inner);
    let swf: Swf = parse(&bytes).expect("parse FWS swf");
    assert_eq!(swf.header.compression, SwfCompression::None);
    assert_eq!(swf.header.frame_count, 1);

    let sprite_tag: &disrobe_pass_as3::SwfTag = swf
        .tags
        .iter()
        .find(|t| t.code == TagCode::DEFINE_SPRITE)
        .expect("expected DefineSprite tag");
    let sprite: disrobe_pass_as3::DefineSprite =
        parse_define_sprite(sprite_tag).expect("parse sprite");
    assert_eq!(sprite.character_id, 42);
    assert_eq!(sprite.frame_count, 3);
    assert!(sprite.tags.iter().any(|t| t.code == TagCode::SHOW_FRAME));
}

#[test]
fn fixture_b_swf_with_do_abc() {
    let abc_blob: Vec<u8> = build_minimal_abc_blob();
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&0_u32.to_le_bytes());
    payload.extend_from_slice(b"Script");
    payload.push(0);
    payload.extend_from_slice(&abc_blob);

    let body_inner: Vec<u8> = pack_short_tag(TagCode::DO_ABC.0, &payload);
    let bytes: Vec<u8> = build_swf(&body_inner);
    let swf: Swf = parse(&bytes).expect("parse swf");
    let do_abc_tag: &disrobe_pass_as3::SwfTag = swf
        .tags
        .iter()
        .find(|t| t.code == TagCode::DO_ABC)
        .expect("expected DoABC tag");
    let blob: disrobe_pass_as3::DoAbc = parse_do_abc(do_abc_tag).expect("parse do_abc");
    assert_eq!(blob.name, "Script");
    let abc: disrobe_pass_as3::AbcFile =
        disrobe_pass_as3::abc::parse(&blob.abc_bytes).expect("parse abc");
    assert_eq!(abc.minor, ABC_MINOR);
    assert_eq!(abc.major, ABC_MAJOR);
}

#[test]
fn fixture_c_haxe_source_detected() {
    let src: &str = "package com.example;\nclass Main extends haxe.macro.Compiler {\n    static function main() { }\n}\n";
    let report: disrobe_pass_as3::DetectionReport =
        disrobe_pass_as3::detect_source_or_binary(src.as_bytes(), Some("Main.hx"));
    assert!(
        report
            .detected
            .contains(&disrobe_pass_as3::DetectedLanguage::Haxe)
    );
}

#[test]
fn fixture_d_perl_bytecode_blob_detected() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"perlbc\0");
    blob.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    let report: disrobe_pass_as3::DetectionReport =
        disrobe_pass_as3::detect_source_or_binary(&blob, Some("blob.plc"));
    assert!(
        report
            .detected
            .contains(&disrobe_pass_as3::DetectedLanguage::PerlBytecode)
    );
}

#[test]
fn fixture_e_nim_binary_signature() {
    let mut bin: Vec<u8> = vec![0u8; 256];
    let needle: &[u8] = b"NimMain";
    bin[100..100 + needle.len()].copy_from_slice(needle);
    let report: disrobe_pass_as3::DetectionReport =
        disrobe_pass_as3::detect_source_or_binary(&bin, None);
    assert!(
        report
            .detected
            .contains(&disrobe_pass_as3::DetectedLanguage::Nim)
    );
}
