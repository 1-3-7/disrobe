#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::time::{Duration, Instant};

use disrobe_pass_lua::ironbrew2_real::lzw_decompress_base36;

fn base36_digit(value: u32) -> char {
    let v: u32 = value % 36;
    if v < 10 {
        char::from(b'0' + v as u8)
    } else {
        char::from(b'A' + (v - 10) as u8)
    }
}

fn encode_token(out: &mut String, value: u64) {
    let mut digits: Vec<char> = Vec::new();
    let mut v: u64 = value;
    if v == 0 {
        digits.push('0');
    }
    while v != 0 {
        digits.push(base36_digit((v % 36) as u32));
        v /= 36;
    }
    digits.reverse();
    out.push(base36_digit(digits.len() as u32));
    for d in digits {
        out.push(d);
    }
}

fn build_lzw_bomb(token_count: usize) -> String {
    let mut stream: String = String::new();
    encode_token(&mut stream, 65);
    for next_index in 256u64..256u64 + token_count as u64 {
        encode_token(&mut stream, next_index);
    }
    stream
}

#[test]
fn lzw_quadratic_expansion_is_capped_not_oom() {
    let stream: String = build_lzw_bomb(20_000);
    assert!(
        stream.len() < (1 << 20),
        "the bomb input stays small while output would balloon"
    );
    let start: Instant = Instant::now();
    let result: Result<Vec<u8>, disrobe_pass_lua::Error> = lzw_decompress_base36(&stream);
    let elapsed: Duration = start.elapsed();
    assert!(
        result.is_err(),
        "a stream whose output exceeds the ceiling must error, not allocate unbounded"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "capped lzw decompression must not hang, took {elapsed:?}"
    );
}

#[test]
fn lzw_small_legitimate_stream_still_decompresses() {
    let mut stream: String = String::new();
    encode_token(&mut stream, 72);
    encode_token(&mut stream, 73);
    let out: Vec<u8> = lzw_decompress_base36(&stream).expect("small stream decompresses");
    assert_eq!(out, vec![72u8, 73u8]);
}
