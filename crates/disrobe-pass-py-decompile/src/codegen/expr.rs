#![allow(
    clippy::match_same_arms,
    clippy::too_many_lines,
    clippy::if_same_then_else,
    clippy::option_if_let_else,
    clippy::format_push_string,
    clippy::redundant_else,
    clippy::cognitive_complexity
)]

use crate::ast::node::{Arg, Arguments, BoolOpKind, ConstValue, Expr, ExprCtx, Keyword, TypeParam};
use crate::bytecode::opcode::{BinOp, CmpOp, UnaryOp};
use crate::bytecode::version::PyVersion;
use crate::codegen::comprehension;
use crate::codegen::version_dispatch::{self, ExecCallShape, PrintCallShape, use_angle_inequality};
use crate::codegen::{DefaultEmitter, format_bytes_literal, format_string_literal};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Precedence {
    Lowest,
    Lambda,
    IfExpr,
    BoolOr,
    BoolAnd,
    Not,
    Comparison,
    BitOr,
    BitXor,
    BitAnd,
    Shift,
    Add,
    Mul,
    Unary,
    Power,
    Await,
    PostfixCall,
    Atom,
}

const MAX_EMIT_DEPTH: usize = 256;

thread_local! {
    static EMIT_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

struct EmitDepthGuard;

impl EmitDepthGuard {
    fn enter() -> Option<Self> {
        EMIT_DEPTH.with(|slot: &std::cell::Cell<usize>| {
            let depth: usize = slot.get();
            if depth >= MAX_EMIT_DEPTH {
                None
            } else {
                slot.set(depth + 1);
                Some(Self)
            }
        })
    }
}

impl Drop for EmitDepthGuard {
    fn drop(&mut self) {
        EMIT_DEPTH.with(|slot: &std::cell::Cell<usize>| slot.set(slot.get().saturating_sub(1)));
    }
}

#[must_use]
pub fn emit_expr(em: &DefaultEmitter, e: &Expr, version: &PyVersion, parent: Precedence) -> String {
    let Some(_guard): Option<EmitDepthGuard> = EmitDepthGuard::enter() else {
        return "...".to_owned();
    };
    let raw: String = emit_expr_inner(em, e, version);
    let mine: Precedence = expr_precedence(e);
    if mine < parent {
        format!("({raw})")
    } else {
        raw
    }
}

#[must_use]
fn emit_expr_inner(em: &DefaultEmitter, e: &Expr, version: &PyVersion) -> String {
    match e {
        Expr::Constant { value, .. } => emit_const(em, value, version),
        Expr::Name { id, .. } => id.clone(),
        Expr::FormattedValue { .. } => emit_joined_str(em, std::slice::from_ref(e), version),
        Expr::JoinedStr { values, .. } => emit_joined_str(em, values, version),
        Expr::TStr { items, .. } => crate::codegen::tstring_emit::emit_tstring(items, version),
        Expr::BoolOp { op, values } => emit_boolop(em, *op, values, version),
        Expr::NamedExpr { target, value } => format!(
            "({} := {})",
            emit_expr(em, target, version, Precedence::Lowest),
            emit_expr(em, value, version, Precedence::Lowest)
        ),
        Expr::BinOp { left, op, right } => emit_binop(em, left, *op, right, version),
        Expr::UnaryOp { op, operand } => emit_unaryop(em, *op, operand, version),
        Expr::Lambda { args, body } => emit_lambda(em, args, body, version),
        Expr::IfExp { test, body, orelse } => {
            let operand_prec: Precedence = next_prec(Precedence::IfExpr);
            format!(
                "{} if {} else {}",
                emit_expr(em, body, version, operand_prec),
                emit_expr(em, test, version, operand_prec),
                emit_expr(em, orelse, version, Precedence::Lambda)
            )
        }
        Expr::Dict { keys, values } => emit_dict(em, keys, values, version),
        Expr::Set(items) => emit_set(em, items, version),
        Expr::ListComp { elt, generators } => {
            let body: String = comprehension::emit_comp_body(em, elt, generators, version);
            format!("[{body}]")
        }
        Expr::SetComp { elt, generators } => {
            let body: String = comprehension::emit_comp_body(em, elt, generators, version);
            format!("{{{body}}}")
        }
        Expr::DictComp {
            key,
            value,
            generators,
        } => comprehension::emit_dict_comp(em, key, value, generators, version),
        Expr::GeneratorExp { elt, generators } => {
            let body: String = comprehension::emit_comp_body(em, elt, generators, version);
            format!("({body})")
        }
        Expr::Await(inner) => format!("await {}", emit_expr(em, inner, version, Precedence::Unary)),
        Expr::Yield(inner) => match inner {
            None => "(yield)".to_owned(),
            Some(v) => format!("(yield {})", emit_expr(em, v, version, Precedence::Lowest)),
        },
        Expr::YieldFrom(inner) => format!(
            "(yield from {})",
            emit_expr(em, inner, version, Precedence::Lowest)
        ),
        Expr::Compare {
            left,
            ops,
            comparators,
        } => emit_compare(em, left, ops, comparators, version),
        Expr::Call {
            func,
            args,
            keywords,
        } => emit_call(em, func, args, keywords, version),
        Expr::Attribute { value, attr, .. } => {
            let rendered: String = emit_expr(em, value, version, Precedence::PostfixCall);
            if attribute_receiver_needs_parens(value) {
                format!("({rendered}).{attr}")
            } else {
                format!("{rendered}.{attr}")
            }
        }
        Expr::Subscript { value, slice, .. } => format!(
            "{}[{}]",
            emit_expr(em, value, version, Precedence::PostfixCall),
            emit_subscript_slice(em, slice, version)
        ),
        Expr::Starred { value, .. } => {
            format!("*{}", emit_expr(em, value, version, Precedence::Unary))
        }
        Expr::List { elts, .. } => {
            let items: Vec<String> = elts
                .iter()
                .map(|x: &Expr| emit_expr(em, x, version, Precedence::Lowest))
                .collect();
            format!("[{}]", items.join(", "))
        }
        Expr::Tuple { elts, ctx } if elts.is_empty() && matches!(ctx, ExprCtx::Store) => {
            "[]".to_owned()
        }
        Expr::Tuple { elts, .. } => emit_tuple_inner(em, elts, version),
        Expr::Slice { lower, upper, step } => emit_slice(
            em,
            lower.as_deref(),
            upper.as_deref(),
            step.as_deref(),
            version,
        ),
        Expr::EmptyDictUnpack => "{}".to_owned(),
        Expr::EmptyDictKeyUnpack => "**{}".to_owned(),
    }
}

#[must_use]
pub fn expr_precedence(e: &Expr) -> Precedence {
    match e {
        Expr::Constant { value, .. } if const_prints_with_leading_minus(value) => Precedence::Unary,
        Expr::Constant { .. }
        | Expr::Name { .. }
        | Expr::List { .. }
        | Expr::Set(_)
        | Expr::Dict { .. }
        | Expr::ListComp { .. }
        | Expr::SetComp { .. }
        | Expr::DictComp { .. }
        | Expr::GeneratorExp { .. }
        | Expr::JoinedStr { .. }
        | Expr::TStr { .. }
        | Expr::FormattedValue { .. }
        | Expr::EmptyDictUnpack
        | Expr::EmptyDictKeyUnpack => Precedence::Atom,
        Expr::Attribute { .. } | Expr::Subscript { .. } | Expr::Call { .. } => {
            Precedence::PostfixCall
        }
        Expr::Await(_) => Precedence::Await,
        Expr::BinOp { op, .. } => binop_precedence(*op),
        Expr::UnaryOp { op, .. } => match op {
            UnaryOp::Not => Precedence::Not,
            _ => Precedence::Unary,
        },
        Expr::BoolOp { op, .. } => match op {
            BoolOpKind::And => Precedence::BoolAnd,
            BoolOpKind::Or => Precedence::BoolOr,
        },
        Expr::Compare { .. } => Precedence::Comparison,
        Expr::IfExp { .. } => Precedence::IfExpr,
        Expr::Lambda { .. } => Precedence::Lambda,
        Expr::NamedExpr { .. } => Precedence::Atom,
        Expr::Tuple { .. } => Precedence::Atom,
        Expr::Starred { .. } => Precedence::Unary,
        Expr::Slice { .. } => Precedence::Atom,
        Expr::Yield(_) | Expr::YieldFrom(_) => Precedence::Atom,
    }
}

#[must_use]
fn binop_precedence(op: BinOp) -> Precedence {
    match op {
        BinOp::BitOr | BinOp::InplaceBitOr => Precedence::BitOr,
        BinOp::BitXor | BinOp::InplaceBitXor => Precedence::BitXor,
        BinOp::BitAnd | BinOp::InplaceBitAnd => Precedence::BitAnd,
        BinOp::Lshift | BinOp::Rshift | BinOp::InplaceLshift | BinOp::InplaceRshift => {
            Precedence::Shift
        }
        BinOp::Add | BinOp::Sub | BinOp::InplaceAdd | BinOp::InplaceSub => Precedence::Add,
        BinOp::Mul
        | BinOp::MatMul
        | BinOp::TrueDiv
        | BinOp::FloorDiv
        | BinOp::Mod
        | BinOp::OldDivide
        | BinOp::InplaceMul
        | BinOp::InplaceMatMul
        | BinOp::InplaceTrueDiv
        | BinOp::InplaceFloorDiv
        | BinOp::InplaceMod
        | BinOp::InplaceOldDivide => Precedence::Mul,
        BinOp::Pow | BinOp::InplacePow => Precedence::Power,
        BinOp::Generic(_) => Precedence::Add,
    }
}

#[must_use]
fn binop_symbol(op: BinOp) -> &'static str {
    match op {
        BinOp::Add | BinOp::InplaceAdd => "+",
        BinOp::Sub | BinOp::InplaceSub => "-",
        BinOp::Mul | BinOp::InplaceMul => "*",
        BinOp::MatMul | BinOp::InplaceMatMul => "@",
        BinOp::TrueDiv | BinOp::InplaceTrueDiv => "/",
        BinOp::FloorDiv | BinOp::InplaceFloorDiv => "//",
        BinOp::Mod | BinOp::InplaceMod => "%",
        BinOp::Pow | BinOp::InplacePow => "**",
        BinOp::Lshift | BinOp::InplaceLshift => "<<",
        BinOp::Rshift | BinOp::InplaceRshift => ">>",
        BinOp::BitAnd | BinOp::InplaceBitAnd => "&",
        BinOp::BitOr | BinOp::InplaceBitOr => "|",
        BinOp::BitXor | BinOp::InplaceBitXor => "^",
        BinOp::OldDivide | BinOp::InplaceOldDivide => "/",
        BinOp::Generic(_) => "?",
    }
}

#[must_use]
pub fn aug_symbol(op: BinOp) -> &'static str {
    match op {
        BinOp::Add | BinOp::InplaceAdd => "+=",
        BinOp::Sub | BinOp::InplaceSub => "-=",
        BinOp::Mul | BinOp::InplaceMul => "*=",
        BinOp::MatMul | BinOp::InplaceMatMul => "@=",
        BinOp::TrueDiv | BinOp::InplaceTrueDiv => "/=",
        BinOp::FloorDiv | BinOp::InplaceFloorDiv => "//=",
        BinOp::Mod | BinOp::InplaceMod => "%=",
        BinOp::Pow | BinOp::InplacePow => "**=",
        BinOp::Lshift | BinOp::InplaceLshift => "<<=",
        BinOp::Rshift | BinOp::InplaceRshift => ">>=",
        BinOp::BitAnd | BinOp::InplaceBitAnd => "&=",
        BinOp::BitOr | BinOp::InplaceBitOr => "|=",
        BinOp::BitXor | BinOp::InplaceBitXor => "^=",
        BinOp::OldDivide | BinOp::InplaceOldDivide => "/=",
        BinOp::Generic(_) => "?=",
    }
}

#[must_use]
fn cmp_symbol(op: CmpOp, py2_angle: bool) -> &'static str {
    match op {
        CmpOp::Lt => "<",
        CmpOp::Le => "<=",
        CmpOp::Eq => "==",
        CmpOp::Ne => {
            let _: bool = py2_angle;
            "!="
        }
        CmpOp::Gt => ">",
        CmpOp::Ge => ">=",
        CmpOp::In => "in",
        CmpOp::NotIn => "not in",
        CmpOp::Is => "is",
        CmpOp::IsNot => "is not",
        CmpOp::ExcMatch => "exception matches",
        CmpOp::BadEq => "==",
        CmpOp::Generic(_) => "?",
    }
}

#[must_use]
fn unary_symbol(op: UnaryOp) -> &'static str {
    match op {
        UnaryOp::Positive => "+",
        UnaryOp::Negative => "-",
        UnaryOp::Not => "not ",
        UnaryOp::Invert => "~",
        UnaryOp::Repr => "",
    }
}

#[must_use]
fn attribute_receiver_needs_parens(value: &Expr) -> bool {
    match value {
        Expr::Constant {
            value: constant @ (ConstValue::Int(_) | ConstValue::BigInt(_)),
            ..
        } => !const_prints_with_leading_minus(constant),
        _ => false,
    }
}

fn emit_const(em: &DefaultEmitter, v: &ConstValue, version: &PyVersion) -> String {
    match v {
        ConstValue::None => "None".to_owned(),
        ConstValue::Ellipsis => "...".to_owned(),
        ConstValue::True => "True".to_owned(),
        ConstValue::False => "False".to_owned(),
        ConstValue::Int(i) => i.to_string(),
        ConstValue::BigInt(b) => emit_long_literal(b, version),
        ConstValue::Float(f) => emit_float(*f),
        ConstValue::Complex { real, imag } => emit_complex(*real, *imag),
        ConstValue::Str(s) => {
            let literal: String = match latin1_bytes(s) {
                Some(bytes) if version.major() < 3 && !s.is_ascii() => {
                    format_bytes_literal(&bytes).split_off(1)
                }
                _ => format_string_literal(s, em.use_double_quotes),
            };
            format!("{}{literal}", str_const_prefix(em, version))
        }
        ConstValue::Unicode(s) => {
            let literal: String = format_string_literal(s, em.use_double_quotes);
            format!("{}{literal}", unicode_const_prefix(em, version))
        }
        ConstValue::Bytes(b) => format_bytes_literal(b),
        ConstValue::Tuple(items) => {
            let parts: Vec<String> = items
                .iter()
                .map(|c: &ConstValue| emit_const(em, c, version))
                .collect();
            match parts.len() {
                0 => "()".to_owned(),
                1 => format!("({},)", parts[0]),
                _ => format!("({})", parts.join(", ")),
            }
        }
        ConstValue::Frozenset(items) => {
            let parts: Vec<String> = items
                .iter()
                .map(|c: &ConstValue| emit_const(em, c, version))
                .collect();
            if parts.is_empty() {
                "frozenset()".to_owned()
            } else {
                format!("{{{}}}", parts.join(", "))
            }
        }
        ConstValue::Slice { lower, upper, step } => {
            format!(
                "slice({}, {}, {})",
                emit_const(em, lower, version),
                emit_const(em, upper, version),
                emit_const(em, step, version)
            )
        }
        ConstValue::Code(code_ref) => format!("<code object {}>", code_ref.qualname),
    }
}

fn latin1_bytes(s: &str) -> Option<Vec<u8>> {
    s.chars()
        .map(|c: char| u8::try_from(u32::from(c)).ok())
        .collect()
}

#[must_use]
fn str_const_prefix(em: &DefaultEmitter, version: &PyVersion) -> &'static str {
    if version.major() < 3 && em.unicode_literals {
        "b"
    } else {
        ""
    }
}

#[must_use]
fn unicode_const_prefix(em: &DefaultEmitter, version: &PyVersion) -> &'static str {
    if version.major() < 3 && !em.unicode_literals {
        "u"
    } else {
        ""
    }
}

const MARSHAL_LONG_SHIFT: u32 = 15;
const CPYTHON_DECIMAL_LITERAL_LIMBS: usize = 900;
const DECIMAL_CHUNK: u64 = 1_000_000_000;

#[must_use]
pub(crate) fn emit_bigint(b: &crate::ast::node::BigUint) -> String {
    let significant: usize = b
        .digits
        .iter()
        .rposition(|d: &u16| *d != 0)
        .map_or(0, |p: usize| p + 1);
    let limbs: &[u16] = &b.digits[..significant];
    let magnitude: String = if limbs.is_empty() {
        "0".to_owned()
    } else if limbs.len() <= CPYTHON_DECIMAL_LITERAL_LIMBS {
        decimal_magnitude(limbs)
    } else {
        hex_magnitude(limbs)
    };
    if b.sign < 0 && !limbs.is_empty() {
        format!("-{magnitude}")
    } else {
        magnitude
    }
}

#[must_use]
fn decimal_magnitude(limbs: &[u16]) -> String {
    let mut chunks: Vec<u64> = Vec::with_capacity(limbs.len() / 2 + 1);
    for limb in limbs.iter().rev() {
        let mut carry: u64 = u64::from(*limb);
        for chunk in &mut chunks {
            let value: u64 = (*chunk << MARSHAL_LONG_SHIFT) + carry;
            *chunk = value % DECIMAL_CHUNK;
            carry = value / DECIMAL_CHUNK;
        }
        while carry > 0 {
            chunks.push(carry % DECIMAL_CHUNK);
            carry /= DECIMAL_CHUNK;
        }
    }
    let mut out: String = String::with_capacity(chunks.len() * 9);
    for (position, chunk) in chunks.iter().rev().enumerate() {
        if position == 0 {
            out.push_str(&chunk.to_string());
        } else {
            out.push_str(&format!("{chunk:09}"));
        }
    }
    if out.is_empty() {
        out.push('0');
    }
    out
}

#[must_use]
fn hex_magnitude(limbs: &[u16]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut reversed: Vec<u8> = Vec::with_capacity(limbs.len() * 4 + 2);
    let mut acc: u64 = 0;
    let mut acc_bits: u32 = 0;
    for limb in limbs {
        acc += u64::from(*limb) << acc_bits;
        acc_bits += MARSHAL_LONG_SHIFT;
        while acc_bits >= 4 {
            reversed.push(HEX_DIGITS[(acc & 0xF) as usize]);
            acc >>= 4;
            acc_bits -= 4;
        }
    }
    while acc > 0 {
        reversed.push(HEX_DIGITS[(acc & 0xF) as usize]);
        acc >>= 4;
    }
    while reversed.len() > 1 && reversed.last() == Some(&b'0') {
        reversed.pop();
    }
    let mut out: String = String::with_capacity(reversed.len() + 2);
    out.push_str("0x");
    out.extend(reversed.iter().rev().map(|d: &u8| char::from(*d)));
    out
}

#[must_use]
fn emit_long_literal(b: &crate::ast::node::BigUint, version: &PyVersion) -> String {
    let digits: String = emit_bigint(b);
    if version.major() < 3 {
        format!("{digits}L")
    } else {
        digits
    }
}

#[must_use]
pub(crate) fn emit_float(f: f64) -> String {
    if f.is_nan() {
        if f.is_sign_negative() {
            "(1e309 * 0)".to_owned()
        } else {
            "-(1e309 * 0)".to_owned()
        }
    } else if f.is_infinite() {
        if f.is_sign_negative() {
            "-1e309".to_owned()
        } else {
            "1e309".to_owned()
        }
    } else {
        python_float_repr(f)
    }
}

#[must_use]
pub(crate) fn emit_complex(real: f64, imag: f64) -> String {
    if !real.is_finite() || !imag.is_finite() {
        format!("complex({}, {})", emit_float(real), emit_float(imag))
    } else if real == 0.0 {
        format!("{}j", emit_float(imag))
    } else {
        let imag_repr: String = emit_float(imag);
        let imag_sign: &str = if imag_repr.starts_with('-') { "" } else { "+" };
        format!("({}{imag_sign}{imag_repr}j)", emit_float(real))
    }
}

#[must_use]
fn python_float_repr(f: f64) -> String {
    let sign: &str = if f.is_sign_negative() { "-" } else { "" };
    if f == 0.0 {
        return format!("{sign}0.0");
    }
    let scientific: String = format!("{:e}", f.abs());
    let Some((mantissa, exponent)): Option<(&str, &str)> = scientific.split_once('e') else {
        return format!("{f:?}");
    };
    let Ok(exponent): Result<i64, std::num::ParseIntError> = exponent.parse::<i64>() else {
        return format!("{f:?}");
    };
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let decimal_point: i64 = exponent + 1;
    let digit_count: i64 = digits.len() as i64;
    let body: String = if decimal_point <= -4 || decimal_point > 16 {
        let (lead, rest): (&str, &str) = digits.split_at(1);
        let exp: i64 = decimal_point - 1;
        let exp_sign: char = if exp < 0 { '-' } else { '+' };
        if rest.is_empty() {
            format!("{lead}e{exp_sign}{:02}", exp.unsigned_abs())
        } else {
            format!("{lead}.{rest}e{exp_sign}{:02}", exp.unsigned_abs())
        }
    } else if decimal_point <= 0 {
        let zeros: String = "0".repeat((-decimal_point) as usize);
        format!("0.{zeros}{digits}")
    } else if decimal_point >= digit_count {
        let zeros: String = "0".repeat((decimal_point - digit_count) as usize);
        format!("{digits}{zeros}.0")
    } else {
        let (int_part, frac_part): (&str, &str) = digits.split_at(decimal_point as usize);
        format!("{int_part}.{frac_part}")
    };
    format!("{sign}{body}")
}

#[must_use]
fn const_prints_with_leading_minus(v: &ConstValue) -> bool {
    match v {
        ConstValue::Int(i) => *i < 0,
        ConstValue::BigInt(b) => b.sign < 0 && b.digits.iter().any(|d: &u16| *d != 0),
        ConstValue::Float(f) => emit_float(*f).starts_with('-'),
        ConstValue::Complex { real, imag } => {
            real.is_finite()
                && imag.is_finite()
                && *real == 0.0
                && emit_float(*imag).starts_with('-')
        }
        _ => false,
    }
}

#[must_use]
fn emit_boolop(
    em: &DefaultEmitter,
    op: BoolOpKind,
    values: &[Expr],
    version: &PyVersion,
) -> String {
    let prec: Precedence = match op {
        BoolOpKind::And => Precedence::BoolAnd,
        BoolOpKind::Or => Precedence::BoolOr,
    };
    let keeps_constant_test: bool = (version.major(), version.minor()) >= (3, 14);
    let parts: Vec<String> = values
        .iter()
        .enumerate()
        .map(|(index, v): (usize, &Expr)| {
            let rendered: String = emit_expr(em, v, version, prec);
            let folds_at_codegen: bool = matches!(
                v,
                Expr::Constant {
                    value: ConstValue::Int(0..) | ConstValue::BigInt(_),
                    ..
                }
            ) || matches!(
                v,
                Expr::Constant { value: ConstValue::Float(f), .. } if f.is_sign_positive()
            );
            if keeps_constant_test && folds_at_codegen && index + 1 < values.len() {
                format!("+{rendered}")
            } else {
                rendered
            }
        })
        .collect();
    let sep: &str = match op {
        BoolOpKind::And => " and ",
        BoolOpKind::Or => " or ",
    };
    parts.join(sep)
}

#[must_use]
fn emit_binop(
    em: &DefaultEmitter,
    left: &Expr,
    op: BinOp,
    right: &Expr,
    version: &PyVersion,
) -> String {
    let prec: Precedence = binop_precedence(op);
    let (lhs_prec, rhs_prec): (Precedence, Precedence) =
        if matches!(op, BinOp::Pow | BinOp::InplacePow) {
            (next_prec(prec), prec)
        } else {
            (prec, next_prec(prec))
        };
    format!(
        "{} {} {}",
        emit_expr(em, left, version, lhs_prec),
        binop_symbol(op),
        emit_expr(em, right, version, rhs_prec)
    )
}

#[must_use]
fn next_prec(p: Precedence) -> Precedence {
    match p {
        Precedence::Lowest => Precedence::Lambda,
        Precedence::Lambda => Precedence::IfExpr,
        Precedence::IfExpr => Precedence::BoolOr,
        Precedence::BoolOr => Precedence::BoolAnd,
        Precedence::BoolAnd => Precedence::Not,
        Precedence::Not => Precedence::Comparison,
        Precedence::Comparison => Precedence::BitOr,
        Precedence::BitOr => Precedence::BitXor,
        Precedence::BitXor => Precedence::BitAnd,
        Precedence::BitAnd => Precedence::Shift,
        Precedence::Shift => Precedence::Add,
        Precedence::Add => Precedence::Mul,
        Precedence::Mul => Precedence::Unary,
        Precedence::Unary => Precedence::Power,
        Precedence::Power => Precedence::Await,
        Precedence::Await => Precedence::PostfixCall,
        Precedence::PostfixCall | Precedence::Atom => Precedence::Atom,
    }
}

#[must_use]
fn emit_unaryop(em: &DefaultEmitter, op: UnaryOp, operand: &Expr, version: &PyVersion) -> String {
    if matches!(op, UnaryOp::Repr) {
        return format!("`{}`", emit_expr(em, operand, version, Precedence::Atom));
    }
    let prec: Precedence = match op {
        UnaryOp::Not => Precedence::Not,
        _ => Precedence::Unary,
    };
    format!(
        "{}{}",
        unary_symbol(op),
        emit_expr(em, operand, version, prec)
    )
}

#[must_use]
fn emit_compare(
    em: &DefaultEmitter,
    left: &Expr,
    ops: &[CmpOp],
    comparators: &[Expr],
    version: &PyVersion,
) -> String {
    let mut out: String = emit_compare_operand(em, left, version);
    let py2_angle: bool = use_angle_inequality(version);
    for (op, rhs) in ops.iter().zip(comparators.iter()) {
        out.push(' ');
        out.push_str(cmp_symbol(*op, py2_angle));
        out.push(' ');
        out.push_str(&emit_compare_operand(em, rhs, version));
    }
    out
}

fn emit_compare_operand(em: &DefaultEmitter, operand: &Expr, version: &PyVersion) -> String {
    if matches!(operand, Expr::Compare { .. }) {
        return format!("({})", emit_expr(em, operand, version, Precedence::Lowest));
    }
    emit_expr(em, operand, version, Precedence::Comparison)
}

#[must_use]
fn emit_call(
    em: &DefaultEmitter,
    func: &Expr,
    args: &[Expr],
    keywords: &[Keyword],
    version: &PyVersion,
) -> String {
    if let Expr::Name { id, .. } = func {
        if id == "print"
            && matches!(
                version_dispatch::print_call_shape(version),
                PrintCallShape::PyStatement
            )
        {
            return emit_print_statement(em, args, version);
        }
        if id == "exec"
            && matches!(
                version_dispatch::exec_call_shape(version),
                ExecCallShape::PyStatement
            )
        {
            return emit_exec_statement(em, args, version);
        }
    }
    let func_str: String = emit_expr(em, func, version, Precedence::PostfixCall);
    let legacy_kw_before_star: bool = version.major() < 3
        && keywords.iter().any(|kw: &Keyword| kw.arg.is_some())
        && args
            .iter()
            .any(|a: &Expr| matches!(a, Expr::Starred { .. }));
    let mut parts: Vec<String> = Vec::with_capacity(args.len() + keywords.len());
    if legacy_kw_before_star {
        for a in args
            .iter()
            .filter(|a: &&Expr| !matches!(a, Expr::Starred { .. }))
        {
            parts.push(emit_expr(em, a, version, Precedence::Lowest));
        }
        for kw in keywords.iter().filter(|kw: &&Keyword| kw.arg.is_some()) {
            if let Some(name) = &kw.arg {
                parts.push(format!(
                    "{name}={}",
                    emit_expr(em, &kw.value, version, Precedence::Lowest)
                ));
            }
        }
        for a in args
            .iter()
            .filter(|a: &&Expr| matches!(a, Expr::Starred { .. }))
        {
            parts.push(emit_expr(em, a, version, Precedence::Lowest));
        }
        for kw in keywords.iter().filter(|kw: &&Keyword| kw.arg.is_none()) {
            parts.push(format!(
                "**{}",
                emit_expr(em, &kw.value, version, Precedence::Unary)
            ));
        }
    } else {
        for a in args {
            parts.push(emit_expr(em, a, version, Precedence::Lowest));
        }
        for kw in keywords {
            match &kw.arg {
                Some(name) => parts.push(format!(
                    "{name}={}",
                    emit_expr(em, &kw.value, version, Precedence::Lowest)
                )),
                None => parts.push(format!(
                    "**{}",
                    emit_expr(em, &kw.value, version, Precedence::Unary)
                )),
            }
        }
    }
    format!("{func_str}({})", parts.join(", "))
}

const PRINT_DEST_MARKER: &str = "__DR_PRINT_DEST__";
const PRINT_NONL_MARKER: &str = "__DR_PRINT_NONL__";

fn is_named(expr: &Expr, target: &str) -> bool {
    matches!(expr, Expr::Name { id, .. } if id == target)
}

#[must_use]
fn emit_print_statement(em: &DefaultEmitter, args: &[Expr], version: &PyVersion) -> String {
    let mut rest: &[Expr] = args;
    let mut dest: Option<&Expr> = None;
    if let [first, stream, tail @ ..] = rest
        && is_named(first, PRINT_DEST_MARKER)
    {
        dest = Some(stream);
        rest = tail;
    }
    let mut trailing_comma: bool = false;
    if let [head @ .., last] = rest
        && is_named(last, PRINT_NONL_MARKER)
    {
        trailing_comma = true;
        rest = head;
    }
    let parts: Vec<String> = rest
        .iter()
        .map(|a: &Expr| emit_expr(em, a, version, Precedence::Lowest))
        .collect();
    let prefix: String = match dest {
        Some(stream) => format!(
            "print >> {}",
            emit_expr(em, stream, version, Precedence::Lowest)
        ),
        None => "print".to_owned(),
    };
    let body: String = match (dest.is_some(), parts.is_empty()) {
        (_, true) => prefix,
        (true, false) => format!("{prefix}, {}", parts.join(", ")),
        (false, false) => format!("{prefix} {}", parts.join(", ")),
    };
    if trailing_comma {
        format!("{body},")
    } else {
        body
    }
}

#[must_use]
fn emit_exec_statement(em: &DefaultEmitter, args: &[Expr], version: &PyVersion) -> String {
    let parts: Vec<String> = args
        .iter()
        .map(|a: &Expr| emit_expr(em, a, version, Precedence::Lowest))
        .collect();
    match parts.as_slice() {
        [] => "exec".to_owned(),
        [body] => format!("exec {body}"),
        [body, globals] => format!("exec {body} in {globals}"),
        [body, globals, locals] => format!("exec {body} in {globals} , {locals}"),
        _ => format!("exec {}", parts.join(", ")),
    }
}

#[must_use]
fn emit_dict(
    em: &DefaultEmitter,
    keys: &[Option<Expr>],
    values: &[Expr],
    version: &PyVersion,
) -> String {
    if keys.is_empty() {
        return "{}".to_owned();
    }
    let mut parts: Vec<String> = Vec::with_capacity(keys.len());
    for (k, v) in keys.iter().zip(values.iter()) {
        match k {
            Some(key) => parts.push(format!(
                "{}: {}",
                emit_expr(em, key, version, Precedence::Lowest),
                emit_expr(em, v, version, Precedence::Lowest)
            )),
            None => parts.push(format!(
                "**{}",
                emit_expr(em, v, version, Precedence::Unary)
            )),
        }
    }
    format!("{{{}}}", parts.join(", "))
}

#[must_use]
fn emit_set(em: &DefaultEmitter, items: &[Expr], version: &PyVersion) -> String {
    if items.is_empty() {
        return "set()".to_owned();
    }
    let parts: Vec<String> = items
        .iter()
        .map(|x: &Expr| emit_expr(em, x, version, Precedence::Lowest))
        .collect();
    format!("{{{}}}", parts.join(", "))
}

#[must_use]
fn emit_tuple_inner(em: &DefaultEmitter, elts: &[Expr], version: &PyVersion) -> String {
    let parts: Vec<String> = elts
        .iter()
        .map(|x: &Expr| emit_expr(em, x, version, Precedence::Lambda))
        .collect();
    match parts.len() {
        0 => "()".to_owned(),
        1 => format!("({},)", parts[0]),
        _ => format!("({})", parts.join(", ")),
    }
}

#[must_use]
pub fn emit_assign_tuple_bare(em: &DefaultEmitter, e: &Expr, version: &PyVersion) -> String {
    match e {
        Expr::Tuple { elts, .. } if elts.len() >= 2 => elts
            .iter()
            .map(|x: &Expr| emit_expr(em, x, version, Precedence::Lambda))
            .collect::<Vec<String>>()
            .join(", "),
        _ => emit_expr(em, e, version, Precedence::Lowest),
    }
}

#[must_use]
pub fn emit_assign_target(em: &DefaultEmitter, e: &Expr, version: &PyVersion) -> String {
    match e {
        Expr::Tuple { elts, ctx } if matches!(ctx, ExprCtx::Store) && elts.len() >= 2 => elts
            .iter()
            .map(|x: &Expr| emit_nested_assign_target(em, x, version))
            .collect::<Vec<String>>()
            .join(", "),
        Expr::Tuple { elts, ctx } if matches!(ctx, ExprCtx::Store) && elts.len() == 1 => {
            format!("{},", emit_nested_assign_target(em, &elts[0], version))
        }
        _ => emit_expr(em, e, version, Precedence::Lowest),
    }
}

fn emit_nested_assign_target(em: &DefaultEmitter, e: &Expr, version: &PyVersion) -> String {
    match e {
        Expr::Tuple { elts, ctx } if matches!(ctx, ExprCtx::Store) && elts.len() >= 2 => {
            format!("({})", emit_assign_target(em, e, version))
        }
        Expr::Tuple { elts, ctx } if matches!(ctx, ExprCtx::Store) && elts.len() == 1 => {
            format!("({},)", emit_nested_assign_target(em, &elts[0], version))
        }
        _ => emit_assign_target(em, e, version),
    }
}

#[must_use]
pub fn is_simultaneous_tuple_assign(targets: &[Expr], value: &Expr) -> bool {
    let [
        Expr::Tuple {
            elts: target_elts, ..
        },
    ]: &[Expr] = targets
    else {
        return false;
    };
    let Expr::Tuple {
        elts: value_elts, ..
    }: &Expr = value
    else {
        return false;
    };
    target_elts.len() >= 2
        && target_elts.len() == value_elts.len()
        && target_elts
            .iter()
            .all(|t: &Expr| matches!(t, Expr::Subscript { .. } | Expr::Attribute { .. }))
}

#[must_use]
fn emit_subscript_slice(em: &DefaultEmitter, slice: &Expr, version: &PyVersion) -> String {
    match slice {
        Expr::Constant {
            value: ConstValue::Slice { lower, upper, step },
            ..
        } => emit_const_slice(em, lower, upper, step, version),
        Expr::Tuple { elts, .. } => {
            let parts: Vec<String> = elts
                .iter()
                .map(|x: &Expr| emit_expr(em, x, version, Precedence::Lowest))
                .collect();
            parts.join(", ")
        }
        Expr::Constant {
            value: ConstValue::Tuple(items),
            ..
        } if items.len() >= 2 => {
            let parts: Vec<String> = items
                .iter()
                .map(|c: &ConstValue| emit_const_subscript_elem(em, c, version))
                .collect();
            parts.join(", ")
        }
        _ => emit_expr(em, slice, version, Precedence::Lowest),
    }
}

#[must_use]
fn emit_const_subscript_elem(em: &DefaultEmitter, c: &ConstValue, version: &PyVersion) -> String {
    match c {
        ConstValue::Slice { lower, upper, step } => {
            emit_const_slice(em, lower, upper, step, version)
        }
        other => emit_const(em, other, version),
    }
}

#[must_use]
fn emit_const_slice(
    em: &DefaultEmitter,
    lower: &ConstValue,
    upper: &ConstValue,
    step: &ConstValue,
    version: &PyVersion,
) -> String {
    let l: String = const_slice_bound(em, lower, version);
    let u: String = const_slice_bound(em, upper, version);
    match step {
        ConstValue::None => format!("{l}:{u}"),
        s => format!("{l}:{u}:{}", emit_const(em, s, version)),
    }
}

#[must_use]
fn const_slice_bound(em: &DefaultEmitter, bound: &ConstValue, version: &PyVersion) -> String {
    match bound {
        ConstValue::None => String::new(),
        other => emit_const(em, other, version),
    }
}

#[must_use]
fn emit_slice(
    em: &DefaultEmitter,
    lower: Option<&Expr>,
    upper: Option<&Expr>,
    step: Option<&Expr>,
    version: &PyVersion,
) -> String {
    let l: String = lower
        .map(|e: &Expr| emit_expr(em, e, version, Precedence::Lowest))
        .unwrap_or_default();
    let u: String = upper
        .map(|e: &Expr| emit_expr(em, e, version, Precedence::Lowest))
        .unwrap_or_default();
    match step {
        Some(s) if is_none_constant(s) => format!("{l}:{u}:"),
        Some(s) => format!("{l}:{u}:{}", emit_expr(em, s, version, Precedence::Lowest)),
        None => format!("{l}:{u}"),
    }
}

#[must_use]
fn is_none_constant(e: &Expr) -> bool {
    matches!(
        e,
        Expr::Constant {
            value: ConstValue::None,
            ..
        }
    )
}

#[must_use]
pub fn emit_arguments(em: &DefaultEmitter, args: &Arguments, version: &PyVersion) -> String {
    let mut parts: Vec<String> = Vec::new();
    let positional_count: usize = args.posonly.len() + args.args.len();
    let first_default: usize = positional_count.saturating_sub(args.defaults.len());
    let default_for = |absolute_i: usize| -> Option<&Expr> {
        absolute_i
            .checked_sub(first_default)
            .and_then(|k: usize| args.defaults.get(k))
    };
    for (i, a) in args.posonly.iter().enumerate() {
        parts.push(format_arg(em, a, default_for(i), version));
    }
    if !args.posonly.is_empty() && version_dispatch::supports_positional_only(version) {
        parts.push("/".to_owned());
    }
    for (i, a) in args.args.iter().enumerate() {
        parts.push(format_arg(
            em,
            a,
            default_for(args.posonly.len() + i),
            version,
        ));
    }
    if let Some(v) = &args.vararg {
        parts.push(format!("*{}", format_arg(em, v, None, version)));
    } else if !args.kwonly.is_empty() {
        parts.push("*".to_owned());
    }
    for (i, a) in args.kwonly.iter().enumerate() {
        let default: Option<&Expr> = args
            .kw_defaults
            .get(i)
            .and_then(|o: &Option<Expr>| o.as_ref());
        parts.push(format_arg(em, a, default, version));
    }
    if let Some(k) = &args.kwarg {
        parts.push(format!("**{}", format_arg(em, k, None, version)));
    }
    parts.join(", ")
}

#[must_use]
fn format_arg(em: &DefaultEmitter, a: &Arg, default: Option<&Expr>, version: &PyVersion) -> String {
    let mut s: String = a.arg.clone();
    if let Some(ann) = &a.annotation {
        s.push_str(": ");
        s.push_str(&emit_expr(em, ann, version, Precedence::Lowest));
    }
    if let Some(d) = default {
        if a.annotation.is_some() {
            s.push_str(" = ");
        } else {
            s.push('=');
        }
        s.push_str(&emit_expr(em, d, version, Precedence::Lowest));
    }
    s
}

#[must_use]
fn emit_lambda(em: &DefaultEmitter, args: &Arguments, body: &Expr, version: &PyVersion) -> String {
    let head: String = emit_arguments(em, args, version);
    let body_str: String = emit_expr(em, body, version, Precedence::Lambda);
    if head.is_empty() {
        format!("lambda: {body_str}")
    } else {
        format!("lambda {head}: {body_str}")
    }
}

#[must_use]
pub fn emit_type_params(em: &DefaultEmitter, params: &[TypeParam], version: &PyVersion) -> String {
    if params.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = params
        .iter()
        .map(|p: &TypeParam| emit_type_param(em, p, version))
        .collect();
    format!("[{}]", parts.join(", "))
}

#[must_use]
fn emit_type_param(em: &DefaultEmitter, p: &TypeParam, version: &PyVersion) -> String {
    match p {
        TypeParam::TypeVar {
            name,
            bound,
            default,
        } => {
            let mut s: String = name.clone();
            if let Some(b) = bound {
                s.push_str(": ");
                s.push_str(&emit_expr(em, b, version, Precedence::Lowest));
            }
            if let Some(d) = default {
                s.push_str(" = ");
                s.push_str(&emit_expr(em, d, version, Precedence::Lowest));
            }
            s
        }
        TypeParam::ParamSpec { name, default } => {
            let mut s: String = format!("**{name}");
            if let Some(d) = default {
                s.push_str(" = ");
                s.push_str(&emit_expr(em, d, version, Precedence::Lowest));
            }
            s
        }
        TypeParam::TypeVarTuple { name, default } => {
            let mut s: String = format!("*{name}");
            if let Some(d) = default {
                s.push_str(" = ");
                s.push_str(&emit_expr(em, d, version, Precedence::Lowest));
            }
            s
        }
    }
}

#[must_use]
const fn conversion_suffix(conversion: crate::ast::node::FormatConversion) -> &'static str {
    match conversion {
        crate::ast::node::FormatConversion::Str => "!s",
        crate::ast::node::FormatConversion::Repr => "!r",
        crate::ast::node::FormatConversion::Ascii => "!a",
        crate::ast::node::FormatConversion::None => "",
    }
}

fn push_replacement_field(
    out: &mut String,
    em: &DefaultEmitter,
    value: &Expr,
    conversion: crate::ast::node::FormatConversion,
    format_spec: Option<&Expr>,
    version: &PyVersion,
) {
    out.push('{');
    out.push_str(&emit_expr(em, value, version, Precedence::Lowest));
    out.push_str(conversion_suffix(conversion));
    if let Some(nested) = format_spec {
        out.push(':');
        out.push_str(&emit_format_spec(em, nested, version));
    }
    out.push('}');
}

#[must_use]
fn emit_format_spec(em: &DefaultEmitter, spec: &Expr, version: &PyVersion) -> String {
    match spec {
        Expr::Constant {
            value: ConstValue::Str(s),
            ..
        } => s.clone(),
        Expr::FormattedValue {
            value,
            conversion,
            format_spec,
            ..
        } => {
            let mut out: String = String::new();
            push_replacement_field(
                &mut out,
                em,
                value,
                *conversion,
                format_spec.as_deref(),
                version,
            );
            out
        }
        Expr::JoinedStr { values, .. } => {
            let mut out: String = String::new();
            for v in values {
                match v {
                    Expr::Constant {
                        value: ConstValue::Str(s),
                        ..
                    } => out.push_str(s),
                    Expr::FormattedValue {
                        value,
                        conversion,
                        format_spec,
                        ..
                    } => push_replacement_field(
                        &mut out,
                        em,
                        value,
                        *conversion,
                        format_spec.as_deref(),
                        version,
                    ),
                    other => out.push_str(&emit_expr(em, other, version, Precedence::Lowest)),
                }
            }
            out
        }
        other => emit_expr(em, other, version, Precedence::Lowest),
    }
}

#[derive(Debug)]
enum FStringSeg<'a> {
    Lit(&'a str),
    Field(String),
}

#[derive(Debug, Clone, Copy)]
enum FStringDelim {
    Single(char),
    Triple(char),
}

#[must_use]
fn emit_joined_str(em: &DefaultEmitter, values: &[Expr], version: &PyVersion) -> String {
    let supports_pep701: bool = {
        let (maj, min): (u8, u8) = (version.major(), version.minor());
        maj > 3 || (maj == 3 && min >= 12)
    };
    let inner_em: DefaultEmitter = if supports_pep701 {
        em.clone()
    } else {
        DefaultEmitter {
            use_double_quotes: false,
            ..em.clone()
        }
    };
    let segments: Vec<FStringSeg<'_>> = values
        .iter()
        .map(|v: &Expr| match v {
            Expr::Constant {
                value: ConstValue::Str(s),
                ..
            } => FStringSeg::Lit(s.as_str()),
            Expr::FormattedValue {
                value,
                conversion,
                format_spec,
                ..
            } => {
                let mut field: String = String::from("{");
                field.push_str(&emit_expr(&inner_em, value, version, Precedence::Lowest));
                match conversion {
                    crate::ast::node::FormatConversion::Str => field.push_str("!s"),
                    crate::ast::node::FormatConversion::Repr => field.push_str("!r"),
                    crate::ast::node::FormatConversion::Ascii => field.push_str("!a"),
                    crate::ast::node::FormatConversion::None => {}
                }
                if let Some(spec) = format_spec {
                    field.push(':');
                    field.push_str(&emit_format_spec(&inner_em, spec, version));
                }
                field.push('}');
                FStringSeg::Field(field)
            }
            other => FStringSeg::Field(emit_expr(&inner_em, other, version, Precedence::Lowest)),
        })
        .collect();

    let delim: FStringDelim = if supports_pep701 {
        FStringDelim::Single('"')
    } else {
        select_fstring_delim(&segments)
    };

    let (open, close): (&str, &str) = match delim {
        FStringDelim::Single('"') => ("f\"", "\""),
        FStringDelim::Single(_) => ("f'", "'"),
        FStringDelim::Triple('"') => ("f\"\"\"", "\"\"\""),
        FStringDelim::Triple(_) => ("f'''", "'''"),
    };
    let mut out: String = String::from(open);
    for seg in &segments {
        match seg {
            FStringSeg::Lit(s) => out.push_str(&escape_fstring_lit_for_delim(s, delim)),
            FStringSeg::Field(f) => out.push_str(f),
        }
    }
    out.push_str(close);
    out
}

#[must_use]
fn select_fstring_delim(segments: &[FStringSeg<'_>]) -> FStringDelim {
    let mut field_has_double: bool = false;
    let mut field_has_single: bool = false;
    let mut field_has_triple_double: bool = false;
    let mut field_has_triple_single: bool = false;
    for seg in segments {
        if let FStringSeg::Field(f) = seg {
            if f.contains('"') {
                field_has_double = true;
            }
            if f.contains('\'') {
                field_has_single = true;
            }
            if f.contains("\"\"\"") {
                field_has_triple_double = true;
            }
            if f.contains("'''") {
                field_has_triple_single = true;
            }
        }
    }
    if !field_has_double {
        FStringDelim::Single('"')
    } else if !field_has_single {
        FStringDelim::Single('\'')
    } else if !field_has_triple_double {
        FStringDelim::Triple('"')
    } else if !field_has_triple_single {
        FStringDelim::Triple('\'')
    } else {
        FStringDelim::Triple('"')
    }
}

#[must_use]
fn escape_fstring_lit_for_delim(s: &str, delim: FStringDelim) -> String {
    match delim {
        FStringDelim::Single(q) => escape_fstring_literal(s, q),
        FStringDelim::Triple(q) => escape_fstring_literal_triple(s, q),
    }
}

#[must_use]
fn escape_fstring_literal_triple(s: &str, quote: char) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out: String = String::with_capacity(s.len());
    let mut run: usize = 0;
    for (idx, &ch) in chars.iter().enumerate() {
        match ch {
            '{' => {
                out.push_str("{{");
                run = 0;
            }
            '}' => {
                out.push_str("}}");
                run = 0;
            }
            '\\' => {
                out.push_str("\\\\");
                run = 0;
            }
            '\n' => {
                out.push_str("\\n");
                run = 0;
            }
            '\r' => {
                out.push_str("\\r");
                run = 0;
            }
            c if c == quote => {
                let is_last: bool = idx + 1 == chars.len();
                if run >= 2 || is_last {
                    out.push('\\');
                    out.push(c);
                    run = 0;
                } else {
                    out.push(c);
                    run += 1;
                }
            }
            c => {
                out.push(c);
                run = 0;
            }
        }
    }
    out
}

#[must_use]
fn escape_fstring_literal(s: &str, outer_quote: char) -> String {
    let mut out: String = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '{' => out.push_str("{{"),
            '}' => out.push_str("}}"),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == outer_quote => {
                out.push('\\');
                out.push(c);
            }
            '\0' => out.push_str("\\0"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::node::BigUint;

    fn bigint_expr() -> Expr {
        Expr::Constant {
            value: ConstValue::BigInt(BigUint {
                sign: 1,
                digits: vec![42],
            }),
            line: None,
        }
    }

    #[test]
    fn bigint_const_emits_py2_long_suffix() {
        let emitter: DefaultEmitter = DefaultEmitter::new();
        let expr: Expr = bigint_expr();
        let out: String = emit_expr(&emitter, &expr, &PyVersion::V2_7, Precedence::Lowest);
        assert_eq!(out, "42L");
    }

    #[test]
    fn a_py2_str_with_high_bytes_renders_those_bytes_escaped() {
        let emitter: DefaultEmitter = DefaultEmitter::new();
        let expr: Expr = Expr::Constant {
            value: ConstValue::Str("caf\u{c3}\u{a9}".to_owned()),
            line: None,
        };
        let py2: String = emit_expr(&emitter, &expr, &PyVersion::V2_7, Precedence::Lowest);
        assert_eq!(
            py2, "\"caf\\xc3\\xa9\"",
            "a utf-8 source file would re-encode raw chars"
        );
        let ascii: Expr = Expr::Constant {
            value: ConstValue::Str("plain".to_owned()),
            line: None,
        };
        assert_eq!(
            emit_expr(&emitter, &ascii, &PyVersion::V2_7, Precedence::Lowest),
            "\"plain\""
        );
    }

    #[test]
    fn bigint_const_omits_py3_long_suffix() {
        let emitter: DefaultEmitter = DefaultEmitter::new();
        let expr: Expr = bigint_expr();
        let out: String = emit_expr(&emitter, &expr, &PyVersion::V3_11, Precedence::Lowest);
        assert_eq!(out, "42");
    }

    #[test]
    fn floats_render_as_cpython_repr() {
        let cases: [(f64, &str); 18] = [
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (123_456_789_012_345_678.0, "1.2345678901234568e+17"),
            (1e22, "1e+22"),
            (1.5e300, "1.5e+300"),
            (1e-05, "1e-05"),
            (0.0001, "0.0001"),
            (-0.0, "-0.0"),
            (0.0, "0.0"),
            (0.1, "0.1"),
            (-2.5, "-2.5"),
            (5e-324, "5e-324"),
            (f64::MAX, "1.7976931348623157e+308"),
            (1.0 / 3.0, "0.3333333333333333"),
            (100.0, "100.0"),
            (-1e-7, "-1e-07"),
            (2.5e-320, "2.5e-320"),
            (12345.678, "12345.678"),
        ];
        for (value, expected) in cases {
            assert_eq!(emit_float(value), expected, "repr of {value:e}");
        }
    }

    #[test]
    fn bigints_beyond_the_decimal_literal_limit_render_in_hex() {
        let decimal: BigUint = BigUint {
            sign: -1,
            digits: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };
        assert_eq!(
            emit_bigint(&decimal),
            "-43556142965880123323311949751266331066368"
        );
        let wide: BigUint = BigUint {
            sign: 1,
            digits: vec![0x7FFF; CPYTHON_DECIMAL_LITERAL_LIMBS + 1],
        };
        let rendered: String = emit_bigint(&wide);
        assert_eq!(
            rendered.len(),
            2 + (15 * (CPYTHON_DECIMAL_LITERAL_LIMBS + 1)).div_ceil(4)
        );
        assert!(rendered.starts_with("0x7fff"), "{}", &rendered[..8]);
        assert!(rendered[2..].bytes().skip(1).all(|b: u8| b == b'f'));
    }
}
