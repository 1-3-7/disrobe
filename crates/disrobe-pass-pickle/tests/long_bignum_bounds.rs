#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::panic::catch_unwind;
use std::time::{Duration, Instant};

use disrobe_pass_pickle::{DecodedArg, Error, disassemble};

fn long1(body: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = vec![0x8a, body.len() as u8];
    out.extend_from_slice(body);
    out.push(b'.');
    out
}

fn long4(body_len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(body_len + 6);
    out.push(0x8b);
    out.extend_from_slice(&(body_len as u32).to_le_bytes());
    out.extend(std::iter::repeat_n(0x7fu8, body_len));
    out.push(b'.');
    out
}

#[test]
fn small_and_medium_long_values_decode_identically() {
    let one: Vec<u8> = long1(&[0x01]);
    let d1 = disassemble(&one).expect("1-byte long parses");
    assert_eq!(d1.instructions[0].arg, DecodedArg::Int(1));

    let neg: Vec<u8> = long1(&[0xff]);
    let d2 = disassemble(&neg).expect("negative long parses");
    assert_eq!(d2.instructions[0].arg, DecodedArg::Int(-1));

    let nine: [u8; 9] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00];
    let d3 = disassemble(&long1(&nine)).expect("9-byte long parses as bigint");
    assert_eq!(
        d3.instructions[0].arg,
        DecodedArg::BigInt("18446744073709551615".to_string())
    );

    let at_cap: Vec<u8> = long4(4096);
    disassemble(&at_cap).expect("4096-byte long body still parses");
}

#[test]
fn oversized_long4_body_is_rejected_fast_without_hanging() {
    let bytes: Vec<u8> = long4(4_000_000);
    let start: Instant = Instant::now();
    let err: Error = disassemble(&bytes).expect_err("oversized long body must be rejected");
    let elapsed: Duration = start.elapsed();
    assert!(
        matches!(err, Error::LongTooLong { limit: 4096, .. }),
        "expected LongTooLong, got {err:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "rejection must be immediate, took {elapsed:?}"
    );
}

#[test]
fn cumulative_long_bytes_are_capped() {
    let mut bytes: Vec<u8> = Vec::new();
    for _ in 0..2200u32 {
        bytes.push(0x8a);
        bytes.push(255);
        bytes.extend(std::iter::repeat_n(0x7fu8, 255));
    }
    bytes.push(b'.');
    let start: Instant = Instant::now();
    let err: Error = disassemble(&bytes).expect_err("cumulative long budget must trip");
    let elapsed: Duration = start.elapsed();
    assert!(
        matches!(err, Error::LongBudget { .. }),
        "expected LongBudget, got {err:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "cumulative rejection must be immediate, took {elapsed:?}"
    );
}

#[test]
fn oversized_long_never_panics_under_catch_unwind() {
    for &n in &[4097usize, 65_536, 1_000_000, 16_000_000] {
        let bytes: Vec<u8> = long4(n);
        let outcome: Result<bool, _> = catch_unwind(|| disassemble(&bytes).is_ok());
        assert!(outcome.is_ok(), "disassemble panicked on long4 body {n}");
        assert!(!outcome.unwrap_or(true), "long4 body {n} must be Err");
    }
}

#[test]
fn random_long_headers_never_panic_or_hang() {
    let mut state: u64 = 0x1234_5678_9abc_def1;
    let start: Instant = Instant::now();
    for _ in 0..5_000u32 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let len: usize = (state as usize) % 8192;
        let mut bytes: Vec<u8> = long4(len.min(64));
        bytes.truncate((state as usize) % bytes.len().max(1));
        let _ = catch_unwind(|| disassemble(&bytes).is_ok());
    }
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "random long headers must not hang"
    );
}
