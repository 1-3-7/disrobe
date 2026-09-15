#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_as3::abc::{ABC_MAJOR, ABC_MINOR, parse};
use disrobe_pass_as3::error::Error;

fn u30(mut value: u32, out: &mut Vec<u8>) {
    loop {
        let mut byte: u8 = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn abc_header_with_empty_cpool() -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&ABC_MINOR.to_le_bytes());
    b.extend_from_slice(&ABC_MAJOR.to_le_bytes());
    b.extend(std::iter::repeat_n(0x01u8, 7));
    b
}

#[test]
fn method_param_count_far_exceeding_input_is_rejected_not_allocated() {
    let mut b: Vec<u8> = abc_header_with_empty_cpool();
    u30(2, &mut b);
    u30(0x3FFF_FFFF, &mut b);
    u30(0, &mut b);
    let err: Error = parse(&b).expect_err("absurd param_count must be rejected before allocation");
    assert!(
        matches!(err, Error::AbcPoolCountTooLarge { pool, .. } if pool == "method_param"),
        "expected method_param bound, got {err}"
    );
}

#[test]
fn multiname_typename_param_count_overflow_is_bounded() {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&ABC_MINOR.to_le_bytes());
    b.extend_from_slice(&ABC_MAJOR.to_le_bytes());
    u30(1, &mut b);
    u30(1, &mut b);
    u30(1, &mut b);
    u30(1, &mut b);
    u30(1, &mut b);
    u30(1, &mut b);
    u30(2, &mut b);
    b.push(0x1D);
    u30(0, &mut b);
    u30(0x3FFF_FFFF, &mut b);
    let err: Error = parse(&b).expect_err("absurd typename param count must be rejected");
    assert!(
        matches!(err, Error::AbcPoolCountTooLarge { pool, .. } if pool == "typename_param"),
        "expected typename_param bound, got {err}"
    );
}

#[test]
fn method_body_code_length_past_remaining_buffer_is_rejected() {
    let mut b: Vec<u8> = abc_header_with_empty_cpool();
    u30(1, &mut b);
    u30(0, &mut b);
    u30(0, &mut b);
    u30(0, &mut b);
    b.push(0);
    u30(0, &mut b);
    u30(0, &mut b);
    u30(0, &mut b);
    u30(1, &mut b);
    u30(0, &mut b);
    u30(1, &mut b);
    u30(1, &mut b);
    u30(0, &mut b);
    u30(1, &mut b);
    u30(0x3FFF_FFFF, &mut b);
    let err: Error = parse(&b).expect_err("absurd method body code length must reject");
    assert!(
        matches!(err, Error::AbcBadCodeLen(_)),
        "expected code length bound, got {err}"
    );
}
