#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_native::{
    CryptoPrimitive, Error, FlirtArch, FlirtMatch, FlirtSig, crc16_flirt, detect_crypto_constants,
    match_flirt, parse_flirt,
};

const AES_TE0: [u32; 8] = [
    0xc663_63a5,
    0xf87c_7c84,
    0xee77_7799,
    0xf67b_7b8d,
    0xfff2_f20d,
    0xd66b_6bbd,
    0xde6f_6fb1,
    0x91c5_c554,
];

fn header(feature_flags: u8) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"IDASGN");
    buf.push(0x05);
    buf.push(0x00);
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(feature_flags);
    buf.push(0x00);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&[0u8; 12]);
    buf.push(0x04);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(b"libc");
    buf
}

fn minimal_sig(crc16_be: [u8; 2], variant_mask_byte: u8, pattern_literal: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = header(0x00);
    buf.push(0x01);
    buf.push(0x02);
    buf.push(variant_mask_byte);
    buf.extend_from_slice(pattern_literal);
    buf.push(0x00);
    buf.push(0x04);
    buf.extend_from_slice(&crc16_be);
    buf.push(0x10);
    buf.push(0x00);
    buf.extend_from_slice(b"main");
    buf.push(0x00);
    buf
}

#[test]
fn parses_minimal_real_sig() {
    let sig_bytes: Vec<u8> = minimal_sig([0xBE, 0xEF], 0x00, &[0x55, 0x8B]);
    let sig: FlirtSig = parse_flirt(&sig_bytes).expect("parse minimal sig");
    assert_eq!(sig.header.version, 5);
    assert_eq!(sig.header.arch, FlirtArch::X86);
    assert_eq!(sig.header.library_name, "libc");
    assert_eq!(sig.modules.len(), 1);
    let m: &disrobe_pass_native::FlirtModule = &sig.modules[0];
    assert_eq!(m.crc16, 0xBEEF);
    assert_eq!(m.crc16_len, 4);
    assert_eq!(m.total_length, 16);
    assert_eq!(m.pattern.bytes, vec![0x55, 0x8B]);
    assert_eq!(m.public_names.len(), 1);
    assert_eq!(m.public_names[0].name, "main");
    assert_eq!(m.public_names[0].offset, 0);
    assert!(!m.public_names[0].is_local);
}

#[test]
fn rejects_bad_magic() {
    let mut buf: Vec<u8> = minimal_sig([0xBE, 0xEF], 0x00, &[0x55, 0x8B]);
    buf[0..6].copy_from_slice(b"NOPE!!");
    assert!(matches!(parse_flirt(&buf), Err(Error::SignatureDb(_))));
}

#[test]
fn rejects_truncated_header() {
    let buf: [u8; 4] = [b'I', b'D', b'A', b'S'];
    assert!(matches!(parse_flirt(&buf), Err(Error::Truncated { .. })));
}

#[test]
fn rejects_compressed_body() {
    let mut buf: Vec<u8> = header(0x01);
    buf.push(0x01);
    assert!(matches!(parse_flirt(&buf), Err(Error::SignatureDb(_))));
}

#[test]
fn variant_mask_decodes_wildcard() {
    let sig_bytes: Vec<u8> = minimal_sig([0xBE, 0xEF], 0x01, &[0x8B]);
    let sig: FlirtSig = parse_flirt(&sig_bytes).expect("parse wildcard sig");
    let m: &disrobe_pass_native::FlirtModule = &sig.modules[0];
    assert_eq!(m.pattern.variant_mask & 1, 1);
    assert_eq!(m.pattern.bytes.len(), 2);
    assert_eq!(m.pattern.bytes[1], 0x8B);
}

#[test]
fn crc16_flirt_known_vector() {
    assert_eq!(crc16_flirt(&[0x55, 0x8B]), 0x2C67);
    assert_eq!(crc16_flirt(&[0x90, 0x90, 0x90, 0x90]), 0x43E9);
}

#[test]
fn crypto_constant_surfaced() {
    let mut buf: Vec<u8> = vec![0u8; 256];
    let mut needle: Vec<u8> = Vec::with_capacity(AES_TE0.len() * 4);
    for word in &AES_TE0 {
        needle.extend_from_slice(&word.to_le_bytes());
    }
    buf[64..64 + needle.len()].copy_from_slice(&needle);
    let hits: Vec<disrobe_pass_native::CryptoConstHit> = detect_crypto_constants(&buf);
    assert!(
        hits.iter()
            .any(|h| h.primitive == CryptoPrimitive::AesTtableEnc)
    );
}

#[test]
fn flirt_match_resolves_name() {
    let crc_region: [u8; 4] = [0x90, 0x90, 0x90, 0x90];
    let crc: u16 = crc16_flirt(&crc_region);
    let sig_bytes: Vec<u8> = minimal_sig(crc.to_be_bytes(), 0x00, &[0x55, 0x8B]);
    let sig: FlirtSig = parse_flirt(&sig_bytes).expect("parse match sig");
    let mut image: Vec<u8> = vec![0u8; 32];
    image[8] = 0x55;
    image[9] = 0x8B;
    image[10..14].copy_from_slice(&crc_region);
    let matches: Vec<FlirtMatch> = match_flirt(&sig, &image);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].name, "main");
    assert_eq!(matches[0].image_offset, 8);
}
