#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unreachable_pub,
    dead_code,
    clippy::print_stdout,
    clippy::redundant_pub_crate,
    clippy::std_instead_of_alloc,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use disrobe_pass_php::{PeelLayer, PeelOptions, peel_eval_chain};
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write as _;

const ORIGINAL: &str = "echo 'recovered cleartext 123';";

fn recovered(blob: &[u8]) -> String {
    let report = peel_eval_chain(blob, PeelOptions::default()).expect("peel");
    String::from_utf8_lossy(&report.final_source).into_owned()
}

fn recovered_with(blob: &[u8]) -> (String, disrobe_pass_php::PeelReport) {
    let report = peel_eval_chain(blob, PeelOptions::default()).expect("peel");
    (
        String::from_utf8_lossy(&report.final_source).into_owned(),
        report,
    )
}

fn assert_cleartext(blob: &[u8], expected: &str, layer: PeelLayer) {
    let (got, report) = recovered_with(blob);
    assert_eq!(got, expected, "recovered cleartext mismatch");
    assert!(
        report.layer_counts.contains_key(&layer),
        "expected layer {layer:?} in {:?}",
        report.layer_counts
    );
    assert!(
        !got.contains("base64_decode") && !got.contains("gzdecode") && !got.contains("eval("),
        "output still contains an encoder call: {got}"
    );
}

#[test]
fn strrev_family_recovers_original() {
    let reversed: String = ORIGINAL.chars().rev().collect();
    let blob: String = format!("<?php eval(strrev('{reversed}'));");
    assert_cleartext(blob.as_bytes(), ORIGINAL, PeelLayer::StrRev);
}

#[test]
fn strrev_over_base64_recovers_original() {
    let reversed: Vec<u8> = ORIGINAL.bytes().rev().collect();
    let b64: String = B64.encode(&reversed);
    let blob: String = format!("<?php eval(strrev(base64_decode('{b64}')));");
    assert_cleartext(blob.as_bytes(), ORIGINAL, PeelLayer::StrRev);
}

#[test]
fn gzdecode_family_recovers_original() {
    let mut enc: GzEncoder<Vec<u8>> = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(ORIGINAL.as_bytes()).expect("gz write");
    let gz: Vec<u8> = enc.finish().expect("gz finish");
    let b64: String = B64.encode(&gz);
    let blob: String = format!("<?php eval(gzdecode(base64_decode('{b64}')));");
    assert_cleartext(blob.as_bytes(), ORIGINAL, PeelLayer::GzDecode);
}

#[test]
fn urldecode_family_recovers_original() {
    let encoded: String = percent_encode(ORIGINAL, true);
    let blob: String = format!("<?php eval(urldecode('{encoded}'));");
    assert_cleartext(blob.as_bytes(), ORIGINAL, PeelLayer::UrlDecode);
}

#[test]
fn rawurldecode_family_recovers_original() {
    let encoded: String = percent_encode(ORIGINAL, false);
    let blob: String = format!("<?php eval(rawurldecode('{encoded}'));");
    assert_cleartext(blob.as_bytes(), ORIGINAL, PeelLayer::RawUrlDecode);
}

#[test]
fn hex_escape_family_recovers_original() {
    let escaped: String = ORIGINAL
        .bytes()
        .map(|b: u8| format!("\\x{b:02x}"))
        .collect();
    let blob: String = format!("<?php eval(\"{escaped}\");");
    assert_cleartext(blob.as_bytes(), ORIGINAL, PeelLayer::HexEscape);
}

#[test]
fn pack_hex_family_recovers_original() {
    let hex: String = ORIGINAL.bytes().map(|b: u8| format!("{b:02x}")).collect();
    let blob: String = format!("<?php eval(pack('H*','{hex}'));");
    assert_cleartext(blob.as_bytes(), ORIGINAL, PeelLayer::PackHex);
}

#[test]
fn chr_concat_family_recovers_original() {
    let chained: String = ORIGINAL
        .bytes()
        .map(|b: u8| format!("chr({b})"))
        .collect::<Vec<String>>()
        .join(".");
    let blob: String = format!("<?php eval({chained});");
    assert_cleartext(blob.as_bytes(), ORIGINAL, PeelLayer::ChrConcat);
}

#[test]
fn uudecode_family_recovers_original() {
    let uu: String = uuencode(ORIGINAL.as_bytes());
    let blob: String = format!("<?php eval(convert_uudecode('{uu}'));");
    assert_cleartext(blob.as_bytes(), ORIGINAL, PeelLayer::Uudecode);
}

#[test]
fn single_key_xor_family_recovers_original() {
    let key: &[u8] = b"K3y";
    let cipher: Vec<u8> = ORIGINAL
        .bytes()
        .enumerate()
        .map(|(i, b): (usize, u8)| b ^ key[i % key.len()])
        .collect();
    let b64: String = B64.encode(&cipher);
    let blob: String = format!("<?php eval(xdec(base64_decode('{b64}'),'K3y'));");
    assert_cleartext(blob.as_bytes(), ORIGINAL, PeelLayer::SingleKeyXor);
}

#[test]
fn create_function_unwraps_to_inner_transform() {
    let b64: String = B64.encode(ORIGINAL.as_bytes());
    let blob: String = format!("<?php eval(create_function('', base64_decode('{b64}')));");
    let (got, _report) = recovered_with(blob.as_bytes());
    assert_eq!(got, ORIGINAL, "create_function inner payload not recovered");
}

#[test]
fn composed_chain_strrev_then_b64_then_gzdecode() {
    let mut enc: GzEncoder<Vec<u8>> = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(ORIGINAL.as_bytes()).expect("gz");
    let gz: Vec<u8> = enc.finish().expect("gz");
    let b64: String = B64.encode(&gz);
    let reversed: String = b64.chars().rev().collect();
    let blob: String = format!("<?php eval(gzdecode(base64_decode(strrev('{reversed}'))));");
    let got: String = recovered(blob.as_bytes());
    assert_eq!(got, ORIGINAL, "composed chain did not recover original");
}

fn percent_encode(s: &str, plus_for_space: bool) -> String {
    let mut out: String = String::new();
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' if plus_for_space => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

fn uuencode(data: &[u8]) -> String {
    let mut out: String = String::new();
    for chunk in data.chunks(45) {
        out.push(uu_char(chunk.len() as u8));
        for triple in chunk.chunks(3) {
            let b0: u8 = triple[0];
            let b1: u8 = *triple.get(1).unwrap_or(&0);
            let b2: u8 = *triple.get(2).unwrap_or(&0);
            out.push(uu_char(b0 >> 2));
            out.push(uu_char(((b0 << 4) | (b1 >> 4)) & 0x3f));
            out.push(uu_char(((b1 << 2) | (b2 >> 6)) & 0x3f));
            out.push(uu_char(b2 & 0x3f));
        }
        out.push('\n');
    }
    out.push('`');
    out.push('\n');
    out
}

fn uu_char(v: u8) -> char {
    if v == 0 { '`' } else { (v + b' ') as char }
}
