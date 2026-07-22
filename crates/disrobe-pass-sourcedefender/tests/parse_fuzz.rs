#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

use disrobe_pass_sourcedefender::{
    Error, Result, decode_armored_line, hex_encode, parse_array_envelope, parse_msgpack_envelope,
    parse_pye_frame, recover_layered,
};

const RANDOM_CASES: usize = 4096;
const MAX_CASE_BYTES: usize = 1024;
const STEP_BUDGET: Duration = Duration::from_secs(20);

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    const fn next_u64(&mut self) -> u64 {
        let mut value: u64 = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        let divisor: u64 = u64::try_from(bound).unwrap_or(u64::MAX);
        let value: u64 = self.next_u64() % divisor;
        usize::try_from(value).unwrap_or(0)
    }

    const fn next_byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}

fn assert_err_without_panic<T, F>(operation: F)
where
    F: FnOnce() -> Result<T>,
{
    let outcome: std::thread::Result<Result<T>> = catch_unwind(AssertUnwindSafe(operation));
    assert!(outcome.is_ok(), "entry point panicked");
    let Some(result): Option<Result<T>> = outcome.ok() else {
        return;
    };
    assert!(result.is_err(), "malformed input unexpectedly decoded");
}

fn exercise_without_panic(bytes: &[u8]) {
    let text: String = bytes
        .iter()
        .map(|byte: &u8| char::from(0x20u8.saturating_add(*byte % 0x5f)))
        .collect();
    let outcomes: [std::thread::Result<()>; 4] = [
        catch_unwind(AssertUnwindSafe(|| {
            let _: Result<Vec<u8>> = decode_armored_line(bytes);
        })),
        catch_unwind(AssertUnwindSafe(|| {
            let _: Result<_> = parse_pye_frame(&text);
        })),
        catch_unwind(AssertUnwindSafe(|| {
            let _: Result<_> = parse_msgpack_envelope(bytes);
        })),
        catch_unwind(AssertUnwindSafe(|| {
            let _: Result<_> = parse_array_envelope(bytes);
        })),
    ];
    for outcome in outcomes {
        assert!(outcome.is_ok(), "entry point panicked");
    }
    let layered: std::thread::Result<()> = catch_unwind(AssertUnwindSafe(|| {
        let _: Result<_> = recover_layered(bytes, "parse-fuzz.pye");
    }));
    assert!(layered.is_ok(), "layered recovery panicked");
}

fn deeply_nested_layered_input() -> String {
    let mut text: String = String::from("-----BEGIN PYE FILE-----\n");
    for _ in 0..128 {
        text.push_str("-----BEGIN PYE FILE-----\n");
    }
    text.push_str("00\n");
    for _ in 0..128 {
        text.push_str("-----END PYE FILE-----\n");
    }
    text.push_str("-----END PYE FILE-----\n");
    text
}

#[test]
fn malformed_entry_inputs_return_errors_without_panics() {
    let frame_truncations: [&str; 4] = [
        "",
        "-",
        "-----BEGIN PYE FILE-----",
        "-----BEGIN PYE FILE-----\nGhOt7h7Jm.?sE?I;!%a(cCM6@0X(^n",
    ];
    let msgpack_truncations: [&[u8]; 6] = [b"", &[0xdf], &[0xdd], &[0xc6], &[0xdb], &[0xcf]];
    let mut huge_map: Vec<u8> = vec![0xdf];
    huge_map.extend_from_slice(&u32::MAX.to_be_bytes());
    let mut huge_array: Vec<u8> = vec![0xdd];
    huge_array.extend_from_slice(&u32::MAX.to_be_bytes());
    let mut huge_binary: Vec<u8> = vec![0xc6];
    huge_binary.extend_from_slice(&u32::MAX.to_be_bytes());
    let mut max_integer: Vec<u8> = vec![0xcf];
    max_integer.extend_from_slice(&u64::MAX.to_be_bytes());

    assert_err_without_panic(|| decode_armored_line(b""));
    assert_err_without_panic(|| decode_armored_line(b"z"));
    for text in frame_truncations {
        assert_err_without_panic(|| parse_pye_frame(text));
    }
    for bytes in msgpack_truncations {
        assert_err_without_panic(|| parse_msgpack_envelope(bytes));
        assert_err_without_panic(|| parse_array_envelope(bytes));
    }
    for bytes in [&huge_map, &huge_array, &huge_binary, &max_integer] {
        assert_err_without_panic(|| parse_msgpack_envelope(bytes));
        assert_err_without_panic(|| parse_array_envelope(bytes));
    }

    let nested: String = deeply_nested_layered_input();
    assert_err_without_panic(|| recover_layered(nested.as_bytes(), "nested.pye"));
}

#[test]
fn structured_random_parse_inputs_finish_within_budget_without_panics() {
    let started: Instant = Instant::now();
    let mut rng: XorShift64 = XorShift64::new(0x7e57_6d15_1a2b_3c4d);
    for case_index in 0..RANDOM_CASES {
        let len: usize = rng.next_usize(MAX_CASE_BYTES);
        let mut bytes: Vec<u8> = Vec::with_capacity(len);
        for offset in 0..len {
            let byte: u8 = if (case_index + offset) % 11 == 0 {
                let marker_index: usize = rng.next_usize(8);
                [0x91u8, 0x92, 0xc4, 0xc6, 0xdc, 0xdd, 0xde, 0xdf][marker_index]
            } else {
                rng.next_byte()
            };
            bytes.push(byte);
        }
        exercise_without_panic(&bytes);
    }
    assert!(
        started.elapsed() <= STEP_BUDGET,
        "{RANDOM_CASES} bounded cases exceeded the step budget"
    );
}

#[test]
fn known_armored_fixture_decodes_to_frozen_bytes() {
    let decoded: Vec<u8> =
        decode_armored_line(b"GhOt7h7Jm.?sE?I;!%a(cCM6@0X(^n").expect("known fixture must decode");
    assert_eq!(hex_encode(&decoded), "310dbdb90f30b66ba95503502209b91d");
    let error: Error = decode_armored_line(b"").expect_err("empty armor must be rejected");
    assert!(matches!(error, Error::Base85 { .. }));
}
