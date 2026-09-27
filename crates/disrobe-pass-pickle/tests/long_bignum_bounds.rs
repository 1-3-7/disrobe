#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::panic::catch_unwind;

use disrobe_pass_pickle::disasm::Disassembly;
use disrobe_pass_pickle::{DecodedArg, Error, disassemble};

const LONG4_HEADER_LEN: usize = 5;
const LONG_BODY_BUDGET: usize = 1 << 18;

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
fn oversized_long4_body_is_rejected_at_its_header() {
    let bytes: Vec<u8> = long4(4_000_000);
    let err: Error = disassemble(&bytes).expect_err("oversized long body must be rejected");
    assert!(
        matches!(
            err,
            Error::LongTooLong {
                declared: 4_000_000,
                limit: 4096,
                offset: LONG4_HEADER_LEN,
            }
        ),
        "the declared length must be refused before any body byte is read, got {err:?}"
    );
}

fn repeated_long1(count: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(count * 257 + 1);
    for _ in 0..count {
        bytes.push(0x8a);
        bytes.push(255);
        bytes.extend(std::iter::repeat_n(0x7fu8, 255));
    }
    bytes.push(b'.');
    bytes
}

#[test]
fn cumulative_long_bytes_are_capped() {
    let within: usize = LONG_BODY_BUDGET / 255;
    let accepted: Disassembly =
        disassemble(&repeated_long1(within)).expect("longs within the cumulative budget parse");
    assert_eq!(accepted.instructions.len(), within + 1);
    let err: Error = disassemble(&repeated_long1(within + 1))
        .expect_err("the first long past the cumulative budget must trip it");
    assert!(
        matches!(
            err,
            Error::LongBudget {
                limit: LONG_BODY_BUDGET
            }
        ),
        "expected LongBudget, got {err:?}"
    );
    let err: Error =
        disassemble(&repeated_long1(2200)).expect_err("cumulative long budget must trip");
    assert!(
        matches!(err, Error::LongBudget { .. }),
        "expected LongBudget, got {err:?}"
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
fn random_long_headers_never_panic_and_decode_at_most_one_instruction_per_byte() {
    let mut state: u64 = 0x1234_5678_9abc_def1;
    for _ in 0..5_000u32 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let len: usize = (state as usize) % 8192;
        let mut bytes: Vec<u8> = long4(len.min(64));
        bytes.truncate((state as usize) % bytes.len().max(1));
        let outcome: Result<Option<usize>, _> = catch_unwind(|| {
            disassemble(&bytes)
                .ok()
                .map(|disassembly: Disassembly| disassembly.instructions.len())
        });
        let decoded: Option<usize> =
            outcome.unwrap_or_else(|_| panic!("disassemble panicked on {bytes:02x?}"));
        if let Some(instructions) = decoded {
            assert!(
                instructions <= bytes.len(),
                "{instructions} instructions decoded from {} bytes",
                bytes.len()
            );
        }
    }
}
