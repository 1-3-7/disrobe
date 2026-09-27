#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_core::recon::string_emu::{DecodedString, RunLimits, StringEncoding, text_runs};

const C2: &str = "http://evil.example/c2";

fn utf16be(text: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    out
}

fn utf16le(text: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn utf32le(text: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for ch in text.chars() {
        out.extend_from_slice(&u32::from(ch).to_le_bytes());
    }
    out
}

fn utf32be(text: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for ch in text.chars() {
        out.extend_from_slice(&u32::from(ch).to_be_bytes());
    }
    out
}

#[test]
fn a_utf16be_run_recovers_the_known_original_with_its_encoding() {
    let encoded: Vec<u8> = utf16be(C2);
    let base: u64 = 0x3000;
    let runs: Vec<DecodedString> = text_runs(
        &encoded,
        base,
        StringEncoding::Utf16Be,
        &RunLimits::default(),
    );
    let hit: &DecodedString = runs
        .iter()
        .find(|s: &&DecodedString| s.text.as_deref() == Some(C2))
        .unwrap_or_else(|| panic!("utf-16be original not recovered: {runs:?}"));
    assert_eq!(
        hit.encoding,
        StringEncoding::Utf16Be,
        "a big-endian run must record big-endian, not little-endian"
    );
    assert_eq!(hit.address, base);
    assert_eq!(
        hit.bytes, encoded,
        "the on-the-wire bytes must survive alongside the decoded text"
    );
}

#[test]
fn a_utf16le_run_records_little_endian_and_keeps_its_bytes() {
    let encoded: Vec<u8> = utf16le(C2);
    let runs: Vec<DecodedString> =
        text_runs(&encoded, 0, StringEncoding::Utf16Le, &RunLimits::default());
    let hit: &DecodedString = runs
        .iter()
        .find(|s: &&DecodedString| s.text.as_deref() == Some(C2))
        .unwrap_or_else(|| panic!("utf-16le original not recovered: {runs:?}"));
    assert_eq!(hit.encoding, StringEncoding::Utf16Le);
    assert_eq!(hit.bytes, encoded);
}

#[test]
fn utf32_runs_in_both_endiannesses_record_their_encoding() {
    for (encoded, expected) in [
        (utf32le(C2), StringEncoding::Utf32Le),
        (utf32be(C2), StringEncoding::Utf32Be),
    ] {
        let runs: Vec<DecodedString> = text_runs(&encoded, 0, expected, &RunLimits::default());
        let hit: &DecodedString = runs
            .iter()
            .find(|s: &&DecodedString| s.text.as_deref() == Some(C2))
            .unwrap_or_else(|| panic!("{expected:?} original not recovered: {runs:?}"));
        assert_eq!(hit.encoding, expected);
        assert_eq!(hit.address, 0);
    }
}

#[test]
fn an_invalid_code_unit_ends_a_run_without_ending_the_scan() {
    let mut buffer: Vec<u8> = Vec::new();
    buffer.extend_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
    buffer.extend_from_slice(&0x0011_0000_u32.to_le_bytes());
    buffer.extend_from_slice(&0x0000_D800_u32.to_le_bytes());
    buffer.extend_from_slice(&utf32le(C2));
    let runs: Vec<DecodedString> =
        text_runs(&buffer, 0, StringEncoding::Utf32Le, &RunLimits::default());
    let hit: &DecodedString = runs
        .iter()
        .find(|s: &&DecodedString| s.text.as_deref() == Some(C2))
        .unwrap_or_else(|| {
            panic!("a run behind three unrepresentable code units was lost: {runs:?}")
        });
    assert_eq!(
        hit.address, 12,
        "the surviving run must be anchored past the unrepresentable units"
    );
    assert_eq!(hit.encoding, StringEncoding::Utf32Le);
}

#[test]
fn a_wide_run_is_not_recovered_by_the_opposite_endianness() {
    let encoded: Vec<u8> = utf16be(C2);
    let wrong: Vec<DecodedString> =
        text_runs(&encoded, 0, StringEncoding::Utf16Le, &RunLimits::default());
    assert!(
        !wrong
            .iter()
            .any(|s: &DecodedString| s.text.as_deref() == Some(C2)),
        "a big-endian buffer must not decode as little-endian: {wrong:?}"
    );
}
