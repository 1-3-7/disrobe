#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_wasm_deob::lift_module_faithful_wat;
use wasmparser::{Operator, Parser, Payload};

fn leb_u32(mut v: u32, out: &mut Vec<u8>) {
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

fn sleb_i64(mut v: i64, out: &mut Vec<u8>) {
    loop {
        let byte: u8 = (v as u8) & 0x7f;
        v >>= 7;
        let sign_set: bool = (byte & 0x40) != 0;
        if (v == 0 && !sign_set) || (v == -1 && sign_set) {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

fn section(id: u8, content: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = vec![id];
    leb_u32(content.len() as u32, &mut out);
    out.extend_from_slice(content);
    out
}

fn const_module(result_type: u8, const_body: &[u8]) -> Vec<u8> {
    let mut m: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    m.extend(section(1, &[0x01, 0x60, 0x00, 0x01, result_type]));
    m.extend(section(3, &[0x01, 0x00]));
    let mut body: Vec<u8> = vec![0x00];
    body.extend_from_slice(const_body);
    body.push(0x0b);
    let mut code: Vec<u8> = vec![0x01];
    leb_u32(body.len() as u32, &mut code);
    code.extend(body);
    m.extend(section(10, &code));
    m
}

fn f32_module(bits: u32) -> Vec<u8> {
    let mut c: Vec<u8> = vec![0x43];
    c.extend_from_slice(&bits.to_le_bytes());
    const_module(0x7d, &c)
}

fn f64_module(bits: u64) -> Vec<u8> {
    let mut c: Vec<u8> = vec![0x44];
    c.extend_from_slice(&bits.to_le_bytes());
    const_module(0x7c, &c)
}

fn i32_module(value: i32) -> Vec<u8> {
    let mut c: Vec<u8> = vec![0x41];
    sleb_i64(i64::from(value), &mut c);
    const_module(0x7f, &c)
}

fn i64_module(value: i64) -> Vec<u8> {
    let mut c: Vec<u8> = vec![0x42];
    sleb_i64(value, &mut c);
    const_module(0x7e, &c)
}

fn lifted_bytes(orig: &[u8], tag: &str) -> Result<Vec<u8>, String> {
    let lifted_wat: String =
        lift_module_faithful_wat(orig).ok_or_else(|| format!("{tag}: no lift produced"))?;
    wat::parse_str(&lifted_wat)
        .map_err(|e| format!("{tag}: emitted wat did not reassemble: {e}\n{lifted_wat}"))
}

fn first_const(bytes: &[u8]) -> Option<Operator<'_>> {
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::CodeSectionEntry(body) = payload.expect("payload") {
            let reader: wasmparser::OperatorsReader<'_> = body.get_operators_reader().expect("ops");
            for op in reader {
                let op: Operator<'_> = op.expect("op");
                if matches!(
                    op,
                    Operator::F32Const { .. }
                        | Operator::F64Const { .. }
                        | Operator::I32Const { .. }
                        | Operator::I64Const { .. }
                ) {
                    return Some(op);
                }
            }
        }
    }
    None
}

fn roundtrip_f32(bits: u32) -> Result<u32, String> {
    let lifted: Vec<u8> = lifted_bytes(&f32_module(bits), &format!("f32 0x{bits:08x}"))?;
    match first_const(&lifted) {
        Some(Operator::F32Const { value }) => Ok(value.bits()),
        other => Err(format!("f32 0x{bits:08x}: unexpected const {other:?}")),
    }
}

fn roundtrip_f64(bits: u64) -> Result<u64, String> {
    let lifted: Vec<u8> = lifted_bytes(&f64_module(bits), &format!("f64 0x{bits:016x}"))?;
    match first_const(&lifted) {
        Some(Operator::F64Const { value }) => Ok(value.bits()),
        other => Err(format!("f64 0x{bits:016x}: unexpected const {other:?}")),
    }
}

fn roundtrip_i32(value: i32) -> Result<i32, String> {
    let lifted: Vec<u8> = lifted_bytes(&i32_module(value), &format!("i32 {value}"))?;
    match first_const(&lifted) {
        Some(Operator::I32Const { value }) => Ok(value),
        other => Err(format!("i32 {value}: unexpected const {other:?}")),
    }
}

fn roundtrip_i64(value: i64) -> Result<i64, String> {
    let lifted: Vec<u8> = lifted_bytes(&i64_module(value), &format!("i64 {value}"))?;
    match first_const(&lifted) {
        Some(Operator::I64Const { value }) => Ok(value),
        other => Err(format!("i64 {value}: unexpected const {other:?}")),
    }
}

const fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z: u64 = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[test]
fn f32_const_preserves_sign_infinity_nan_payload_and_finite_bits() {
    let mut failures: Vec<String> = Vec::new();
    let mut check = |bits: u32| match roundtrip_f32(bits) {
        Ok(got) if got == bits => {}
        Ok(got) => failures.push(format!("f32 orig=0x{bits:08x} lifted=0x{got:08x}")),
        Err(e) => failures.push(e),
    };
    for bits in [
        0x0000_0000u32,
        0x8000_0000,
        0x3f80_0000,
        0xbf80_0000,
        0x7f80_0000,
        0xff80_0000,
        0x0000_0001,
        0x007f_ffff,
        0x0080_0000,
        0x7f7f_ffff,
        0xff7f_ffff,
        0x7fc0_0000,
        0xffc0_0000,
        0x7f80_0001,
        0x7fab_cdef,
        0xffab_cdef,
        0x3dcc_cccd,
        0x4049_0fdb,
    ] {
        check(bits);
    }
    for payload in 1u32..=4096 {
        check(0x7f80_0000 | payload);
        check(0xff80_0000 | payload);
    }
    let mut state: u64 = 0x1234_5678_9abc_def0;
    for _ in 0..20000 {
        check(splitmix64(&mut state) as u32);
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn f64_const_preserves_sign_infinity_nan_payload_and_finite_bits() {
    let mut failures: Vec<String> = Vec::new();
    let mut check = |bits: u64| match roundtrip_f64(bits) {
        Ok(got) if got == bits => {}
        Ok(got) => failures.push(format!("f64 orig=0x{bits:016x} lifted=0x{got:016x}")),
        Err(e) => failures.push(e),
    };
    for bits in [
        0x0000_0000_0000_0000u64,
        0x8000_0000_0000_0000,
        0x3ff0_0000_0000_0000,
        0xbff0_0000_0000_0000,
        0x7ff0_0000_0000_0000,
        0xfff0_0000_0000_0000,
        0x0000_0000_0000_0001,
        0x000f_ffff_ffff_ffff,
        0x0010_0000_0000_0000,
        0x7fef_ffff_ffff_ffff,
        0x7ff8_0000_0000_0000,
        0xfff8_0000_0000_0000,
        0x7ff0_0000_0000_0001,
        0x7ff1_2345_6789_abcd,
        0xfff1_2345_6789_abcd,
        0x3fb9_9999_9999_999a,
        0x4009_21fb_5444_2d18,
    ] {
        check(bits);
    }
    for payload in 1u64..=4096 {
        check(0x7ff0_0000_0000_0000 | payload);
        check(0xfff0_0000_0000_0000 | payload);
    }
    let mut state: u64 = 0x0fed_cba9_8765_4321;
    for _ in 0..20000 {
        check(splitmix64(&mut state));
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn integer_const_preserves_sign_and_full_width() {
    let mut failures: Vec<String> = Vec::new();
    for value in [
        0i32,
        -1,
        1,
        i32::MIN,
        i32::MIN + 1,
        i32::MAX,
        i32::MAX - 1,
        -42,
    ] {
        match roundtrip_i32(value) {
            Ok(got) if got == value => {}
            Ok(got) => failures.push(format!("i32 orig={value} lifted={got}")),
            Err(e) => failures.push(e),
        }
    }
    for value in [
        0i64,
        -1,
        1,
        i64::MIN,
        i64::MIN + 1,
        i64::MAX,
        i64::MAX - 1,
        -42,
    ] {
        match roundtrip_i64(value) {
            Ok(got) if got == value => {}
            Ok(got) => failures.push(format!("i64 orig={value} lifted={got}")),
            Err(e) => failures.push(e),
        }
    }
    let mut state: u64 = 0xdead_beef_cafe_babe;
    for _ in 0..10000 {
        let r: u64 = splitmix64(&mut state);
        match roundtrip_i32(r as u32 as i32) {
            Ok(got) if got == r as u32 as i32 => {}
            Ok(got) => failures.push(format!("i32 orig={} lifted={got}", r as u32 as i32)),
            Err(e) => failures.push(e),
        }
        match roundtrip_i64(r as i64) {
            Ok(got) if got == r as i64 => {}
            Ok(got) => failures.push(format!("i64 orig={} lifted={got}", r as i64)),
            Err(e) => failures.push(e),
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
