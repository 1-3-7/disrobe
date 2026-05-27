#![allow(
    clippy::match_same_arms,
    clippy::too_many_lines,
    clippy::if_same_then_else,
    clippy::option_if_let_else,
    clippy::format_push_string,
    clippy::redundant_else,
    clippy::cognitive_complexity
)]

use crate::ast::node::{
    Arg, Arguments, BoolOpKind, ConstValue, Expr, Keyword, TStrItem, TypeParam,
};
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

#[must_use]
pub fn emit_expr(em: &DefaultEmitter, e: &Expr, version: &PyVersion, parent: Precedence) -> String {
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
        Expr::Constant { value, .. } => emit_const(em, value),
        Expr::Name { id, .. } => id.clone(),
        Expr::FormattedValue {
            value,
            conversion,
            format_spec,
            ..
        } => emit_formatted_value(em, value, *conversion, format_spec.as_deref(), version),
        Expr::JoinedStr { values, .. } => emit_joined_str(em, values, version),
        Expr::TStr { items, .. } => emit_tstr(em, items, version),
        Expr::BoolOp { op, values } => emit_boolop(em, *op, values, version),
        Expr::NamedExpr { target, value } => format!(
            "({} := {})",
            emit_expr(em, target, version, Precedence::Lowest),
            emit_expr(em, value, version, Precedence::Lowest)
        ),
        Expr::BinOp { left, op, right } => emit_binop(em, left, *op, right, version),
        Expr::UnaryOp { op, operand } => emit_unaryop(em, *op, operand, version),
        Expr::Lambda { args, body } => emit_lambda(em, args, body, version),
        Expr::IfExp { test, body, orelse } => format!(
            "{} if {} else {}",
            emit_expr(em, body, version, Precedence::Lambda),
            emit_expr(em, test, version, Precedence::Lambda),
            emit_expr(em, orelse, version, Precedence::Lambda)
        ),
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
        Expr::Attribute { value, attr, .. } => format!(
            "{}.{attr}",
            emit_expr(em, value, version, Precedence::PostfixCall)
        ),
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
    }
}

#[must_use]
fn emit_const(em: &DefaultEmitter, v: &ConstValue) -> String {
    match v {
        ConstValue::None => "None".to_owned(),
        ConstValue::Ellipsis => "...".to_owned(),
        ConstValue::True => "True".to_owned(),
        ConstValue::False => "False".to_owned(),
        ConstValue::Int(i) => i.to_string(),
        ConstValue::BigInt(b) => emit_bigint(b),
        ConstValue::Float(f) => emit_float(*f),
        ConstValue::Complex { real, imag } => {
            if *real == 0.0 {
                format!("{}j", emit_float(*imag))
            } else {
                format!("({}{:+}j)", emit_float(*real), imag)
            }
        }
        ConstValue::Str(s) => format_string_literal(s, em.use_double_quotes),
        ConstValue::Bytes(b) => format_bytes_literal(b),
        ConstValue::Tuple(items) => {
            let parts: Vec<String> = items
                .iter()
                .map(|c: &ConstValue| emit_const(em, c))
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
                .map(|c: &ConstValue| emit_const(em, c))
                .collect();
            format!("frozenset({{{}}})", parts.join(", "))
        }
        ConstValue::Code(code_ref) => format!("<code object {}>", code_ref.qualname),
    }
}

#[must_use]
fn emit_bigint(b: &crate::ast::node::BigUint) -> String {
    let mut acc: u128 = 0u128;
    let mut shift: u32 = 0u32;
    for d in &b.digits {
        acc |= u128::from(*d) << shift;
        shift = shift.saturating_add(16);
        if shift >= 128 {
            return "0".to_owned();
        }
    }
    if b.sign < 0 {
        format!("-{acc}")
    } else {
        acc.to_string()
    }
}

#[must_use]
fn emit_float(f: f64) -> String {
    if f.is_nan() {
        "float('nan')".to_owned()
    } else if f.is_infinite() {
        if f.is_sign_negative() {
            "float('-inf')".to_owned()
        } else {
            "float('inf')".to_owned()
        }
    } else if f.fract() == 0.0 && f.abs() < 1e16 {
        format!("{f:.1}")
    } else {
        format!("{f}")
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
    let parts: Vec<String> = values
        .iter()
        .map(|v: &Expr| emit_expr(em, v, version, prec))
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
    let mut out: String = emit_expr(em, left, version, Precedence::Comparison);
    let py2_angle: bool = use_angle_inequality(version);
    for (op, rhs) in ops.iter().zip(comparators.iter()) {
        out.push(' ');
        out.push_str(cmp_symbol(*op, py2_angle));
        out.push(' ');
        out.push_str(&emit_expr(em, rhs, version, Precedence::Comparison));
    }
    out
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
    let mut parts: Vec<String> = Vec::with_capacity(args.len() + keywords.len());
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
    format!("{func_str}({})", parts.join(", "))
}

#[must_use]
fn emit_print_statement(em: &DefaultEmitter, args: &[Expr], version: &PyVersion) -> String {
    let parts: Vec<String> = args
        .iter()
        .map(|a: &Expr| emit_expr(em, a, version, Precedence::Lowest))
        .collect();
    if parts.is_empty() {
        "print".to_owned()
    } else {
        format!("print {}", parts.join(", "))
    }
}

#[must_use]
fn emit_exec_statement(em: &DefaultEmitter, args: &[Expr], version: &PyVersion) -> String {
    let parts: Vec<String> = args
        .iter()
        .map(|a: &Expr| emit_expr(em, a, version, Precedence::Lowest))
        .collect();
    if parts.is_empty() {
        "exec".to_owned()
    } else {
        format!("exec {}", parts.join(", "))
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
fn emit_subscript_slice(em: &DefaultEmitter, slice: &Expr, version: &PyVersion) -> String {
    match slice {
        Expr::Tuple { elts, .. } => {
            let parts: Vec<String> = elts
                .iter()
                .map(|x: &Expr| emit_expr(em, x, version, Precedence::Lowest))
                .collect();
            parts.join(", ")
        }
        _ => emit_expr(em, slice, version, Precedence::Lowest),
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
        Some(s) => format!("{l}:{u}:{}", emit_expr(em, s, version, Precedence::Lowest)),
        None => format!("{l}:{u}"),
    }
}

#[must_use]
pub fn emit_arguments(em: &DefaultEmitter, args: &Arguments, version: &PyVersion) -> String {
    let mut parts: Vec<String> = Vec::new();
    let pos_default_offset: usize = args.args.len().saturating_sub(args.defaults.len());
    let posonly_default_offset: usize = if args.posonly.is_empty() {
        0
    } else {
        let total_pos: usize = args.posonly.len() + args.args.len();
        total_pos.saturating_sub(args.defaults.len())
    };
    for (i, a) in args.posonly.iter().enumerate() {
        let default: Option<&Expr> = if i >= posonly_default_offset {
            args.defaults.get(i - posonly_default_offset)
        } else {
            None
        };
        parts.push(format_arg(em, a, default, version));
    }
    if !args.posonly.is_empty() && version_dispatch::supports_positional_only(version) {
        parts.push("/".to_owned());
    }
    let pos_d_base: usize = args.posonly.len();
    for (i, a) in args.args.iter().enumerate() {
        let absolute_i: usize = pos_d_base + i;
        let default: Option<&Expr> = if absolute_i >= pos_default_offset + pos_d_base {
            args.defaults
                .get(absolute_i - (pos_default_offset + pos_d_base))
        } else if !args.posonly.is_empty() {
            None
        } else if i >= pos_default_offset {
            args.defaults.get(i - pos_default_offset)
        } else {
            None
        };
        parts.push(format_arg(em, a, default, version));
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
fn emit_formatted_value(
    em: &DefaultEmitter,
    value: &Expr,
    conversion: crate::ast::node::FormatConversion,
    format_spec: Option<&Expr>,
    version: &PyVersion,
) -> String {
    let inner: String = emit_expr(em, value, version, Precedence::Lowest);
    let conv: &str = match conversion {
        crate::ast::node::FormatConversion::Str => "!s",
        crate::ast::node::FormatConversion::Repr => "!r",
        crate::ast::node::FormatConversion::Ascii => "!a",
        crate::ast::node::FormatConversion::None => "",
    };
    let spec: String = match format_spec {
        Some(s) => format!(":{}", emit_format_spec(em, s, version)),
        None => String::new(),
    };
    format!("f\"{{{inner}{conv}{spec}}}\"")
}

#[must_use]
fn emit_format_spec(em: &DefaultEmitter, spec: &Expr, version: &PyVersion) -> String {
    match spec {
        Expr::Constant {
            value: ConstValue::Str(s),
            ..
        } => s.clone(),
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
                    } => {
                        out.push('{');
                        out.push_str(&emit_expr(em, value, version, Precedence::Lowest));
                        match conversion {
                            crate::ast::node::FormatConversion::Str => out.push_str("!s"),
                            crate::ast::node::FormatConversion::Repr => out.push_str("!r"),
                            crate::ast::node::FormatConversion::Ascii => out.push_str("!a"),
                            crate::ast::node::FormatConversion::None => {}
                        }
                        if let Some(nested) = format_spec.as_deref() {
                            out.push(':');
                            out.push_str(&emit_format_spec(em, nested, version));
                        }
                        out.push('}');
                    }
                    other => out.push_str(&emit_expr(em, other, version, Precedence::Lowest)),
                }
            }
            out
        }
        other => emit_expr(em, other, version, Precedence::Lowest),
    }
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
    let outer_quote: char = '"';
    let mut out: String = String::from("f");
    out.push(outer_quote);
    for v in values {
        match v {
            Expr::Constant {
                value: ConstValue::Str(s),
                ..
            } => out.push_str(&escape_fstring_literal(s, outer_quote)),
            Expr::FormattedValue {
                value,
                conversion,
                format_spec,
                ..
            } => {
                out.push('{');
                out.push_str(&emit_expr(&inner_em, value, version, Precedence::Lowest));
                match conversion {
                    crate::ast::node::FormatConversion::Str => out.push_str("!s"),
                    crate::ast::node::FormatConversion::Repr => out.push_str("!r"),
                    crate::ast::node::FormatConversion::Ascii => out.push_str("!a"),
                    crate::ast::node::FormatConversion::None => {}
                }
                if let Some(spec) = format_spec {
                    out.push(':');
                    out.push_str(&emit_format_spec(&inner_em, spec, version));
                }
                out.push('}');
            }
            other => out.push_str(&emit_expr(&inner_em, other, version, Precedence::Lowest)),
        }
    }
    out.push(outer_quote);
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
            c => out.push(c),
        }
    }
    out
}

#[must_use]
fn emit_tstr(em: &DefaultEmitter, items: &[TStrItem], version: &PyVersion) -> String {
    let mut out: String = String::from("t\"");
    for item in items {
        match item {
            TStrItem::Literal(s) => out.push_str(&escape_fstring_literal(s, '"')),
            TStrItem::Interp {
                value,
                conversion,
                format_spec,
            } => {
                out.push('{');
                out.push_str(&emit_expr(em, value, version, Precedence::Lowest));
                match conversion {
                    crate::ast::node::FormatConversion::Str => out.push_str("!s"),
                    crate::ast::node::FormatConversion::Repr => out.push_str("!r"),
                    crate::ast::node::FormatConversion::Ascii => out.push_str("!a"),
                    crate::ast::node::FormatConversion::None => {}
                }
                if let Some(spec) = format_spec {
                    out.push(':');
                    out.push_str(&emit_format_spec(em, spec, version));
                }
                out.push('}');
            }
        }
    }
    out.push('"');
    out
}
