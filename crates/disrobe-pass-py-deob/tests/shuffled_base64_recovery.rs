#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_py_deob::{PeelResult, peel};

const STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const PE_DOS_STUB_ANCHOR: &[u8] = b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

fn shuffle_alphabet(seed: u64) -> [u8; 64] {
    let mut alphabet: [u8; 64] = *STANDARD_ALPHABET;
    let mut state: u64 = seed;
    for i in (1..64).rev() {
        state = state
            .wrapping_mul(0x5851_f42d_4c95_7f2d)
            .wrapping_add(0x1405_7b7e_f767_814f);
        let j: usize = (state >> 33) as usize % (i + 1);
        alphabet.swap(i, j);
    }
    alphabet
}

fn encode_with_alphabet(data: &[u8], alphabet: &[u8; 64]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(data.len() * 4 / 3 + 4);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            let index: usize = ((accumulator >> bits) & 0x3f) as usize;
            out.push(alphabet[index]);
        }
    }
    if bits > 0 {
        let index: usize = ((accumulator << (6 - bits)) & 0x3f) as usize;
        out.push(alphabet[index]);
    }
    out
}

fn synthetic_pe() -> Vec<u8> {
    let mut pe: Vec<u8> = PE_DOS_STUB_ANCHOR.to_vec();
    pe.extend_from_slice(b"PE\x00\x00");
    for byte in 0u16..=255 {
        pe.push(byte as u8);
    }
    for byte in 0u16..=255 {
        pe.push((255 - byte) as u8);
    }
    pe
}

fn anchor_covered_pe() -> Vec<u8> {
    let mut pe: Vec<u8> = PE_DOS_STUB_ANCHOR.to_vec();
    pe.extend_from_slice(&[0u8; 384]);
    pe
}

fn synthetic_zip() -> Vec<u8> {
    let mut zip: Vec<u8> = vec![0x50, 0x4b, 0x03, 0x04, 0x14, 0x00];
    zip.extend_from_slice(&[0u8; 24]);
    zip.extend_from_slice(b"payload.txtdata bytes here for the local file entry");
    zip
}

fn synthetic_elf() -> Vec<u8> {
    let mut elf: Vec<u8> = vec![0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00];
    elf.extend_from_slice(&[0u8; 8]);
    elf.extend_from_slice(&[0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00]);
    elf.extend_from_slice(b"executable section body content padding");
    elf
}

fn synthetic_png() -> Vec<u8> {
    let mut png: Vec<u8> = vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    png.extend_from_slice(&[0x00, 0x00, 0x00, 0x0d]);
    png.extend_from_slice(b"IHDR");
    png.extend_from_slice(&[0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10]);
    png.extend_from_slice(b"image pixel chunk payload bytes");
    png
}

fn utf16le_bom() -> Vec<u8> {
    let mut text: Vec<u8> = vec![0xff, 0xfe];
    for ch in "powershell -enc payload".chars() {
        text.extend_from_slice(&(ch as u16).to_le_bytes());
    }
    text
}

fn utf16be_bom() -> Vec<u8> {
    let mut text: Vec<u8> = vec![0xfe, 0xff];
    for ch in "windows command shell payload".chars() {
        text.extend_from_slice(&(ch as u16).to_be_bytes());
    }
    text
}

#[test]
fn shuffled_alphabet_pe_recovers_exact_plaintext() {
    let original: Vec<u8> = anchor_covered_pe();
    let alphabet: [u8; 64] = shuffle_alphabet(0x9e37_79b9_7f4a_7c15);
    assert_ne!(alphabet, *STANDARD_ALPHABET, "alphabet must be permuted");

    let encoded: Vec<u8> = encode_with_alphabet(&original, &alphabet);
    let standard: Vec<u8> = encode_with_alphabet(&original, STANDARD_ALPHABET);
    assert_ne!(
        encoded, standard,
        "shuffled encoding must differ from standard"
    );

    let result: PeelResult = peel(&encoded).expect("peel must not error");
    assert!(
        result.recovered,
        "shuffled-base64 PE must be recovered; steps: {steps:?}",
        steps = result.steps
    );
    let labels: Vec<&str> = result.steps.iter().map(|s| s.decoder.as_str()).collect();
    assert!(
        labels.iter().any(|l: &&str| l.contains("base64-shuffled")),
        "expected a base64-shuffled step, got {labels:?}"
    );
    assert!(
        labels.iter().any(|l: &&str| l.contains("pe-mz")),
        "recovery must be labeled pe-mz, got {labels:?}"
    );
    assert!(
        result.final_source.contains("pe-mz"),
        "summary must name the artifact type: {summary}",
        summary = result.final_source
    );
}

#[test]
fn shuffled_alphabet_decode_matches_original_byte_for_byte() {
    let original: Vec<u8> = anchor_covered_pe();
    let alphabet: [u8; 64] = shuffle_alphabet(0x0102_0304_0506_0708);
    let encoded: Vec<u8> = encode_with_alphabet(&original, &alphabet);

    let mut inverse: [i16; 256] = [-1; 256];
    for (index, &symbol) in alphabet.iter().enumerate() {
        inverse[symbol as usize] = index as i16;
    }
    let mut decoded: Vec<u8> = Vec::new();
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for &symbol in &encoded {
        let value: i16 = inverse[symbol as usize];
        assert!(value >= 0, "encoded symbol outside the shuffled alphabet");
        accumulator = (accumulator << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push((accumulator >> bits) as u8);
        }
    }
    assert_eq!(
        decoded, original,
        "self-consistency: shuffled encode then alphabet-decode is the identity"
    );

    let result: PeelResult = peel(&encoded).expect("peel");
    assert!(result.recovered);
}

#[test]
fn standard_base64_pe_accepted_and_labeled() {
    let original: Vec<u8> = synthetic_pe();
    let encoded: Vec<u8> = encode_with_alphabet(&original, STANDARD_ALPHABET);
    let result: PeelResult = peel(&encoded).expect("peel");
    assert!(result.recovered, "standard-base64 PE must be recovered");
    assert!(
        result.final_source.contains("pe-mz"),
        "summary: {s}",
        s = result.final_source
    );
}

#[test]
fn standard_base64_zip_accepted_and_labeled() {
    let original: Vec<u8> = synthetic_zip();
    let encoded: Vec<u8> = encode_with_alphabet(&original, STANDARD_ALPHABET);
    let result: PeelResult = peel(&encoded).expect("peel");
    assert!(
        result.recovered,
        "zip must be recovered; steps: {steps:?}",
        steps = result.steps
    );
    assert!(
        result.final_source.contains("zip"),
        "summary: {s}",
        s = result.final_source
    );
}

#[test]
fn standard_base64_elf_accepted_and_labeled() {
    let original: Vec<u8> = synthetic_elf();
    let encoded: Vec<u8> = encode_with_alphabet(&original, STANDARD_ALPHABET);
    let result: PeelResult = peel(&encoded).expect("peel");
    assert!(
        result.recovered,
        "elf must be recovered; steps: {steps:?}",
        steps = result.steps
    );
    assert!(
        result.final_source.contains("elf"),
        "summary: {s}",
        s = result.final_source
    );
}

#[test]
fn standard_base64_png_accepted_and_labeled() {
    let original: Vec<u8> = synthetic_png();
    let encoded: Vec<u8> = encode_with_alphabet(&original, STANDARD_ALPHABET);
    let result: PeelResult = peel(&encoded).expect("peel");
    assert!(
        result.recovered,
        "png must be recovered; steps: {steps:?}",
        steps = result.steps
    );
    assert!(
        result.final_source.contains("png"),
        "summary: {s}",
        s = result.final_source
    );
}

#[test]
fn standard_base64_utf16_boms_accepted_and_labeled() {
    for (blob, label) in [(utf16le_bom(), "utf-16le"), (utf16be_bom(), "utf-16be")] {
        let encoded: Vec<u8> = encode_with_alphabet(&blob, STANDARD_ALPHABET);
        let result: PeelResult = peel(&encoded).expect("peel");
        assert!(result.recovered, "{label} blob must be recovered");
        assert!(
            result.final_source.contains(label),
            "summary for {label}: {s}",
            s = result.final_source
        );
    }
}

#[test]
fn high_entropy_base64_without_crib_is_not_falsely_decoded() {
    let mut blob: Vec<u8> = Vec::with_capacity(192);
    let mut state: u64 = 0xdead_beef_cafe_babe;
    for _ in 0..192 {
        state = state
            .wrapping_mul(0x5851_f42d_4c95_7f2d)
            .wrapping_add(0x1405_7b7e_f767_814f);
        blob.push((state >> 33) as u8);
    }
    let encoded: Vec<u8> = encode_with_alphabet(&blob, STANDARD_ALPHABET);
    let result: PeelResult = peel(&encoded).expect("peel");
    assert!(
        !result.final_source.contains("recovered embedded"),
        "must not fabricate a crib match on random bytes"
    );
    assert!(
        !result
            .steps
            .iter()
            .any(|s| s.decoder.contains("base64-shuffled")),
        "random bytes must never trigger a shuffled-base64 recovery: {steps:?}",
        steps = result.steps
    );
}
