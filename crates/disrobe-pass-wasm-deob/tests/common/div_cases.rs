#![allow(dead_code, unreachable_pub)]

pub const DIV_REM_MODULE: &str = r#"(module
  (func (export "i32_div_s") (param i32 i32) (result i32) local.get 0 local.get 1 i32.div_s)
  (func (export "i32_div_u") (param i32 i32) (result i32) local.get 0 local.get 1 i32.div_u)
  (func (export "i32_rem_s") (param i32 i32) (result i32) local.get 0 local.get 1 i32.rem_s)
  (func (export "i32_rem_u") (param i32 i32) (result i32) local.get 0 local.get 1 i32.rem_u)
  (func (export "i64_div_s") (param i64 i64) (result i64) local.get 0 local.get 1 i64.div_s)
  (func (export "i64_div_u") (param i64 i64) (result i64) local.get 0 local.get 1 i64.div_u)
  (func (export "i64_rem_s") (param i64 i64) (result i64) local.get 0 local.get 1 i64.rem_s)
  (func (export "i64_rem_u") (param i64 i64) (result i64) local.get 0 local.get 1 i64.rem_u)
)"#;

pub struct I32Case {
    pub a: i32,
    pub b: i32,
    pub div_s: i32,
    pub div_u: i32,
    pub rem_s: i32,
    pub rem_u: i32,
}

pub struct I64Case {
    pub a: i64,
    pub b: i64,
    pub div_s: i64,
    pub div_u: i64,
    pub rem_s: i64,
    pub rem_u: i64,
}

#[must_use]
pub fn i32_cases() -> Vec<I32Case> {
    vec![
        I32Case {
            a: 0xFFFF_FFFFu32 as i32,
            b: 2,
            div_s: 0,
            div_u: 2_147_483_647,
            rem_s: -1,
            rem_u: 1,
        },
        I32Case {
            a: -7,
            b: 3,
            div_s: -2,
            div_u: 1_431_655_763,
            rem_s: -1,
            rem_u: 0,
        },
        I32Case {
            a: i32::MIN,
            b: 7,
            div_s: -306_783_378,
            div_u: 306_783_378,
            rem_s: -2,
            rem_u: 2,
        },
    ]
}

#[must_use]
pub fn i64_cases() -> Vec<I64Case> {
    vec![
        I64Case {
            a: 0xFFFF_FFFF_FFFF_FFFFu64 as i64,
            b: 2,
            div_s: 0,
            div_u: 9_223_372_036_854_775_807,
            rem_s: -1,
            rem_u: 1,
        },
        I64Case {
            a: -7,
            b: 3,
            div_s: -2,
            div_u: 6_148_914_691_236_517_203,
            rem_s: -1,
            rem_u: 0,
        },
    ]
}
