#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::panic::{AssertUnwindSafe, catch_unwind};

use disrobe_pass_wasm_deob::{
    FunctionFingerprint, analyze_module, detect, extract_signatures, fingerprint_module,
    strip_name_section,
};

const ARITH4: &[u8] = include_bytes!("fixtures/arith4.wasm");
const MAGIC: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

fn leb(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte: u8 = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

fn drive(bytes: &[u8]) -> bool {
    let owned: Vec<u8> = bytes.to_vec();
    let outcome: std::thread::Result<()> = catch_unwind(AssertUnwindSafe(|| {
        let _ = strip_name_section(&owned);
        let _ = fingerprint_module(&owned);
        let _ = detect(&owned);
        let _ = analyze_module(&owned);
        let _ = extract_signatures(&owned);
    }));
    outcome.is_ok()
}

#[test]
fn malformed_section_streams_never_panic() {
    let mut cases: Vec<Vec<u8>> = Vec::new();

    for id in 0u8..=20 {
        for length in [
            vec![0x00u8],
            vec![0xff, 0xff, 0xff, 0xff, 0x0f],
            vec![0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
            vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x80],
            vec![0x7f],
        ] {
            let mut buf: Vec<u8> = MAGIC.to_vec();
            buf.push(id);
            buf.extend_from_slice(&length);
            cases.push(buf);
        }
    }

    let mut overflow_len: Vec<u8> = MAGIC.to_vec();
    overflow_len.push(0x00);
    leb(u64::from(u32::MAX), &mut overflow_len);
    cases.push(overflow_len);

    for n in 0..=MAGIC.len() {
        cases.push(MAGIC[..n].to_vec());
    }

    let mut many_empty: Vec<u8> = MAGIC.to_vec();
    for _ in 0..200_000 {
        many_empty.push(0x00);
        many_empty.push(0x00);
    }
    cases.push(many_empty);

    for (index, case) in cases.iter().enumerate() {
        assert!(
            drive(case),
            "unwound on crafted case {index} len={}",
            case.len()
        );
    }
}

#[test]
fn random_bytes_after_magic_never_panic() {
    let mut state: u64 = 0x51ed_2701_abcd_9f13;
    for _ in 0..4_000 {
        let len: usize = (state % 512) as usize;
        let mut buf: Vec<u8> = MAGIC.to_vec();
        for _ in 0..len {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            buf.push((state >> 33) as u8);
        }
        assert!(drive(&buf), "unwound on random input len={}", buf.len());
    }
}

#[test]
fn strip_name_section_preserves_bodies_on_wellformed_module() {
    let stripped: Vec<u8> = strip_name_section(ARITH4).expect("strip");
    let before: Vec<FunctionFingerprint> = fingerprint_module(ARITH4).expect("fp before");
    let after: Vec<FunctionFingerprint> = fingerprint_module(&stripped).expect("fp after");
    assert_eq!(before.len(), after.len());
    for (a, b) in before.iter().zip(after.iter()) {
        assert_eq!(a.exact_hash, b.exact_hash);
    }
}
