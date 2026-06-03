#![allow(
    dead_code,
    clippy::redundant_pub_crate,
    clippy::match_same_arms,
    clippy::missing_const_for_fn
)]

pub(crate) mod band;
pub(crate) mod tokenize;

use disrobe_pass_py_decompile::ast::{ConstValue, Expr, ExprCtx};
use disrobe_pass_py_decompile::bytecode::version::PyVersion as DecompileVersion;
use disrobe_py_marshal::{CodeEra, CodeObject, Object, PyVersion};

#[must_use]
pub(crate) fn ver(major: u8, minor: u8) -> DecompileVersion {
    match (major, minor) {
        (3, 8) => DecompileVersion::V3_8,
        (3, 9) => DecompileVersion::V3_9,
        (3, 10) => DecompileVersion::V3_10,
        (3, 11) => DecompileVersion::V3_11,
        (3, 13) => DecompileVersion::V3_13,
        (3, 14) => DecompileVersion::V3_14,
        (3, 15) => DecompileVersion::V3_15,
        _ => DecompileVersion::V3_12,
    }
}

#[must_use]
pub(crate) fn name(id: &str) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    }
}

#[must_use]
pub(crate) fn name_store(id: &str) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx: ExprCtx::Store,
        line: None,
    }
}

#[must_use]
pub(crate) fn int(n: i128) -> Expr {
    Expr::Constant {
        value: ConstValue::Int(n),
        line: None,
    }
}

#[must_use]
pub(crate) fn str_lit(s: &str) -> Expr {
    Expr::Constant {
        value: ConstValue::Str(s.to_owned()),
        line: None,
    }
}

#[must_use]
pub(crate) fn bool_lit(b: bool) -> Expr {
    Expr::Constant {
        value: if b {
            ConstValue::True
        } else {
            ConstValue::False
        },
        line: None,
    }
}

#[must_use]
pub(crate) fn empty_code(version: PyVersion) -> CodeObject {
    let era: CodeEra = disrobe_py_marshal::code_era_for(version);
    let mut code: CodeObject = CodeObject::new(era);
    code.filename = Object::None;
    code.name = Object::None;
    code.qualname = Object::None;
    code
}

#[must_use]
pub(crate) fn encode_varint(value: u64, is_first: bool) -> Vec<u8> {
    let mut bits: Vec<u8> = Vec::new();
    let mut v: u64 = value;
    loop {
        bits.push(u8::try_from(v & 0x3F).unwrap_or(0));
        v >>= 6;
        if v == 0 {
            break;
        }
    }
    bits.reverse();
    let n: usize = bits.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    for (i, chunk) in bits.iter().enumerate() {
        let mut byte: u8 = *chunk;
        if i + 1 < n {
            byte |= 0x40;
        }
        if i == 0 && is_first {
            byte |= 0x80;
        }
        out.push(byte);
    }
    out
}

#[must_use]
pub(crate) fn encode_exc_entry(
    start_units: u64,
    length_units: u64,
    target_units: u64,
    depth: u64,
    lasti: bool,
) -> Vec<u8> {
    let dl: u64 = (depth << 1) | u64::from(lasti);
    let mut out: Vec<u8> = Vec::new();
    out.extend(encode_varint(start_units, true));
    out.extend(encode_varint(length_units, false));
    out.extend(encode_varint(target_units, false));
    out.extend(encode_varint(dl, false));
    out
}
