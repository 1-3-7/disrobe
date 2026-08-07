#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::missing_const_for_fn,
    clippy::items_after_statements
)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use disrobe_core::codec::DecodeError;
use disrobe_core::codec::hex::{
    HexDecodeOptions, OddTail, STRICT, TOKEN, TRUNCATING, WRAPPED_STREAM, WRAPPED_STREAM_NONEMPTY,
    decode_with,
};

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x: u64 = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }

    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next_u64() as usize) % (hi - lo + 1)
    }
}

fn guard<F: FnOnce()>(label: &str, desc: &str, f: F) {
    let result: std::thread::Result<()> = catch_unwind(AssertUnwindSafe(f));
    assert!(result.is_ok(), "{label} unwound on fuzz input ({desc})");
}

fn profiles() -> Vec<(&'static str, HexDecodeOptions)> {
    vec![
        ("strict", STRICT),
        ("token", TOKEN),
        ("truncating", TRUNCATING),
        ("wrapped_stream", WRAPPED_STREAM),
        ("wrapped_stream_nonempty", WRAPPED_STREAM_NONEMPTY),
        ("strict_pad_high", STRICT.with_odd_tail(OddTail::PadHigh)),
        (
            "wrapped_stream_pad_high",
            WRAPPED_STREAM.with_odd_tail(OddTail::PadHigh),
        ),
        ("strict_capped_8", STRICT.with_max_input_bytes(8)),
        (
            "wrapped_stream_capped_4",
            WRAPPED_STREAM.with_max_input_bytes(4),
        ),
    ]
}

fn drive_bytes(bytes: &[u8], desc: &str) {
    for (label, options) in profiles() {
        guard(label, desc, || {
            let outcome: Result<Vec<u8>, DecodeError> = decode_with(bytes, options);
            if let Ok(decoded) = &outcome {
                assert!(
                    decoded.len() <= bytes.len(),
                    "{label} grew the output past the input length on {desc}"
                );
            }
        });
    }
}

fn hex_biased_alphabet() -> &'static [u8] {
    b"0123456789abcdefABCDEF \t\r\n:-xX\0\x7f\x80\xff.,;+g\xc3\xb0"
}

fn mutate(rng: &mut XorShift64, base: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = base.to_vec();
    let op: usize = rng.range(0, 6);
    match op {
        0 => {
            if !buf.is_empty() {
                let cut: usize = rng.range(0, buf.len());
                buf.truncate(cut);
            }
        }
        1 => {
            if !buf.is_empty() {
                let idx: usize = rng.range(0, buf.len() - 1);
                let bit: u8 = 1u8 << rng.range(0, 7);
                buf[idx] ^= bit;
            }
        }
        2 => {
            if !buf.is_empty() {
                let idx: usize = rng.range(0, buf.len() - 1);
                buf[idx] = rng.byte();
            }
        }
        3 => {
            let extra: usize = rng.range(1, 64);
            let alphabet: &[u8] = hex_biased_alphabet();
            for _ in 0..extra {
                let pick: usize = rng.range(0, alphabet.len() - 1);
                buf.push(alphabet[pick]);
            }
        }
        4 => {
            if buf.len() >= 2 {
                let a: usize = rng.range(0, buf.len() - 1);
                let b: usize = rng.range(0, buf.len() - 1);
                buf.swap(a, b);
            }
        }
        _ => {
            let idx: usize = if buf.is_empty() {
                0
            } else {
                rng.range(0, buf.len())
            };
            let count: usize = rng.range(1, 16);
            let alphabet: &[u8] = hex_biased_alphabet();
            for i in 0..count {
                let pick: usize = rng.range(0, alphabet.len() - 1);
                buf.insert(
                    idx.min(buf.len()).saturating_add(i).min(buf.len()),
                    alphabet[pick],
                );
            }
        }
    }
    buf
}

fn seed_corpus() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        b" ".to_vec(),
        b"   ".to_vec(),
        b"\t\r\n".to_vec(),
        b"a".to_vec(),
        b"ab".to_vec(),
        b"abc".to_vec(),
        b"de ad\tbe\r\nef".to_vec(),
        b"0x1234".to_vec(),
        b"\\x41\\x42".to_vec(),
        b"de:ad:be:ef".to_vec(),
        b"AbCdEf0123456789".to_vec(),
        vec![0x00, b'0', 0xff, 0x80],
    ]
}

#[test]
fn seeded_mutations_never_panic() {
    let mut rng: XorShift64 = XorShift64::new(0x00C0_FFEE_D15E_A5E5);
    let corpus: Vec<Vec<u8>> = seed_corpus();
    const ITERATIONS: usize = 6000;
    for i in 0..ITERATIONS {
        let base: &Vec<u8> = &corpus[i % corpus.len()];
        let mutated: Vec<u8> = mutate(&mut rng, base);
        drive_bytes(&mutated, "seeded-mutation");
    }
}

#[test]
fn random_bytes_never_panic() {
    let mut rng: XorShift64 = XorShift64::new(0x5EED_C0DE_F00D_BA11);
    const ITERATIONS: usize = 4000;
    for _ in 0..ITERATIONS {
        let len: usize = rng.range(0, 512);
        let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        drive_bytes(&bytes, "pure-random");
    }
}

#[test]
fn every_error_stays_within_the_three_variants_hex_decode_can_construct() {
    let mut rng: XorShift64 = XorShift64::new(0x1337_D00D_CAFE_F00D);
    let corpus: Vec<Vec<u8>> = seed_corpus();
    const ITERATIONS: usize = 3000;
    for i in 0..ITERATIONS {
        let base: &Vec<u8> = &corpus[i % corpus.len()];
        let mutated: Vec<u8> = mutate(&mut rng, base);
        for (_, options) in profiles() {
            match decode_with(&mutated, options) {
                Ok(_)
                | Err(
                    DecodeError::TooLarge { .. }
                    | DecodeError::BadLength { .. }
                    | DecodeError::InvalidSymbol { .. },
                ) => {}
                Err(other) => panic!("decode_with returned an unexpected variant: {other:?}"),
            }
        }
    }
}
