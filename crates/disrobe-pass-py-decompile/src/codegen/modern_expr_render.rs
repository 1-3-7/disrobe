use crate::ast::node::{BoolOpKind, ConstValue, Expr, FormatConversion, Keyword, TStrItem};
use crate::bytecode::opcode::{BinOp, CmpOp, UnaryOp};
use crate::bytecode::version::PyVersion;

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render_expr(expr: &Expr, version: &PyVersion) -> String {
    match expr {
        Expr::Constant { value, .. } => render_const(value),
        Expr::Name { id, .. } => id.clone(),
        Expr::Attribute { value, attr, .. } => {
            format!("{}.{attr}", render_expr(value, version))
        }
        Expr::Subscript { value, slice, .. } => {
            format!(
                "{}[{}]",
                render_expr(value, version),
                render_expr(slice, version)
            )
        }
        Expr::BinOp { left, op, right } => {
            format!(
                "{} {} {}",
                render_expr(left, version),
                render_binop(*op),
                render_expr(right, version)
            )
        }
        Expr::UnaryOp { op, operand } => {
            if matches!(op, UnaryOp::Repr) {
                format!("`{}`", render_expr(operand, version))
            } else {
                format!("{}{}", render_unaryop(*op), render_expr(operand, version))
            }
        }
        Expr::BoolOp { op, values } => {
            let sep: &str = match op {
                BoolOpKind::And => " and ",
                BoolOpKind::Or => " or ",
            };
            values
                .iter()
                .map(|v: &Expr| render_expr(v, version))
                .collect::<Vec<String>>()
                .join(sep)
        }
        Expr::Compare {
            left,
            ops,
            comparators,
        } => {
            let mut out: String = render_expr(left, version);
            for (op, rhs) in ops.iter().zip(comparators.iter()) {
                out.push(' ');
                out.push_str(render_cmpop(*op));
                out.push(' ');
                out.push_str(&render_expr(rhs, version));
            }
            out
        }
        Expr::Call {
            func,
            args,
            keywords,
        } => render_call(func, args, keywords, version),
        Expr::Tuple { elts, .. } => render_tuple(elts, version),
        Expr::List { elts, .. } => {
            let inner: String = elts
                .iter()
                .map(|e: &Expr| render_expr(e, version))
                .collect::<Vec<String>>()
                .join(", ");
            format!("[{inner}]")
        }
        Expr::Set(elts) => {
            if elts.is_empty() {
                "set()".to_owned()
            } else {
                let inner: String = elts
                    .iter()
                    .map(|e: &Expr| render_expr(e, version))
                    .collect::<Vec<String>>()
                    .join(", ");
                format!("{{{inner}}}")
            }
        }
        Expr::Dict { keys, values } => render_dict(keys, values, version),
        Expr::Starred { value, .. } => format!("*{}", render_expr(value, version)),
        Expr::IfExp { test, body, orelse } => format!(
            "{} if {} else {}",
            render_expr(body, version),
            render_expr(test, version),
            render_expr(orelse, version)
        ),
        Expr::Slice { lower, upper, step } => {
            render_slice(lower.as_deref(), upper.as_deref(), step.as_deref(), version)
        }
        Expr::Lambda { args: _, body } => format!("lambda: {}", render_expr(body, version)),
        Expr::NamedExpr { target, value } => format!(
            "({} := {})",
            render_expr(target, version),
            render_expr(value, version)
        ),
        Expr::Await(inner) => format!("await {}", render_expr(inner, version)),
        Expr::Yield(opt) => opt.as_deref().map_or_else(
            || "yield".to_owned(),
            |e: &Expr| format!("yield {}", render_expr(e, version)),
        ),
        Expr::YieldFrom(inner) => format!("yield from {}", render_expr(inner, version)),
        Expr::JoinedStr { values, .. } => render_joinedstr(values, version),
        Expr::TStr { items, .. } => render_tstr(items, version),
        Expr::FormattedValue {
            value,
            conversion,
            format_spec,
            ..
        } => {
            let mut inner: String = render_expr(value, version);
            inner.push_str(conversion_suffix(*conversion));
            if let Some(spec) = format_spec.as_deref() {
                inner.push(':');
                inner.push_str(&render_format_spec_inner(spec, version));
            }
            format!("{{{inner}}}")
        }
        Expr::ListComp { elt, .. } => format!("[{}]", render_expr(elt, version)),
        Expr::SetComp { elt, .. } => format!("{{{}}}", render_expr(elt, version)),
        Expr::DictComp { key, value, .. } => format!(
            "{{{}: {}}}",
            render_expr(key, version),
            render_expr(value, version)
        ),
        Expr::GeneratorExp { elt, .. } => format!("({})", render_expr(elt, version)),
        Expr::EmptyDictUnpack => "**{}".to_owned(),
        Expr::EmptyDictKeyUnpack => "{**{}}".to_owned(),
    }
}

#[must_use]
pub fn render_const(value: &ConstValue) -> String {
    match value {
        ConstValue::None => "None".to_owned(),
        ConstValue::Ellipsis => "...".to_owned(),
        ConstValue::True => "True".to_owned(),
        ConstValue::False => "False".to_owned(),
        ConstValue::Int(i) => i.to_string(),
        ConstValue::BigInt(big) => crate::codegen::expr::emit_bigint(big),
        ConstValue::Float(f) => format_float(*f),
        ConstValue::Complex { real, imag } => {
            if *real == 0.0 {
                format!("{}j", format_float(*imag))
            } else {
                format!("({}+{}j)", format_float(*real), format_float(*imag))
            }
        }
        ConstValue::Str(s) | ConstValue::Unicode(s) => render_string_literal(s),
        ConstValue::Bytes(b) => render_bytes_literal(b),
        ConstValue::Tuple(elts) => {
            let inner: String = elts
                .iter()
                .map(render_const)
                .collect::<Vec<String>>()
                .join(", ");
            if elts.len() == 1 {
                format!("({inner},)")
            } else {
                format!("({inner})")
            }
        }
        ConstValue::Frozenset(elts) => {
            let inner: String = elts
                .iter()
                .map(render_const)
                .collect::<Vec<String>>()
                .join(", ");
            format!("frozenset({{{inner}}})")
        }
        ConstValue::Code(c) => format!("<code {}>", c.qualname),
    }
}

#[must_use]
fn format_float(f: f64) -> String {
    if f.is_nan() {
        if f.is_sign_negative() {
            "float('-nan')".to_owned()
        } else {
            "float('nan')".to_owned()
        }
    } else if f.is_infinite() {
        if f > 0.0 {
            "1e309".to_owned()
        } else {
            "-1e309".to_owned()
        }
    } else if f.fract() == 0.0 && f.abs() < 1e16 {
        format!("{f:.1}")
    } else {
        format!("{f}")
    }
}

#[must_use]
pub fn render_string_literal(s: &str) -> String {
    let mut needs_double: bool = false;
    let mut needs_single: bool = false;
    for c in s.chars() {
        match c {
            '"' => needs_single = true,
            '\'' => needs_double = true,
            _ => {}
        }
    }
    let quote: char = if needs_double && !needs_single {
        '\''
    } else {
        '"'
    };
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

#[must_use]
fn render_bytes_literal(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out: String = String::with_capacity(b.len() + 3);
    out.push_str("b\"");
    for &byte in b {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(byte as char),
            _ => {
                let _ = write!(out, "\\x{byte:02x}");
            }
        }
    }
    out.push('"');
    out
}

#[must_use]
const fn render_binop(op: BinOp) -> &'static str {
    match op {
        BinOp::Add | BinOp::InplaceAdd => "+",
        BinOp::Sub | BinOp::InplaceSub => "-",
        BinOp::Mul | BinOp::InplaceMul => "*",
        BinOp::MatMul | BinOp::InplaceMatMul => "@",
        BinOp::TrueDiv | BinOp::InplaceTrueDiv | BinOp::OldDivide | BinOp::InplaceOldDivide => "/",
        BinOp::FloorDiv | BinOp::InplaceFloorDiv => "//",
        BinOp::Mod | BinOp::InplaceMod => "%",
        BinOp::Pow | BinOp::InplacePow => "**",
        BinOp::Lshift | BinOp::InplaceLshift => "<<",
        BinOp::Rshift | BinOp::InplaceRshift => ">>",
        BinOp::BitAnd | BinOp::InplaceBitAnd => "&",
        BinOp::BitOr | BinOp::InplaceBitOr => "|",
        BinOp::BitXor | BinOp::InplaceBitXor => "^",
        BinOp::Generic(_) => "?",
    }
}

#[must_use]
const fn render_unaryop(op: UnaryOp) -> &'static str {
    match op {
        UnaryOp::Positive => "+",
        UnaryOp::Negative => "-",
        UnaryOp::Not => "not ",
        UnaryOp::Invert => "~",
        UnaryOp::Repr => "",
    }
}

#[must_use]
const fn render_cmpop(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Lt => "<",
        CmpOp::Le => "<=",
        CmpOp::Eq | CmpOp::BadEq => "==",
        CmpOp::Ne => "!=",
        CmpOp::Gt => ">",
        CmpOp::Ge => ">=",
        CmpOp::In => "in",
        CmpOp::NotIn => "not in",
        CmpOp::Is => "is",
        CmpOp::IsNot => "is not",
        CmpOp::ExcMatch => "match",
        CmpOp::Generic(_) => "?",
    }
}

#[must_use]
fn render_call(func: &Expr, args: &[Expr], keywords: &[Keyword], version: &PyVersion) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(args.len() + keywords.len());
    for a in args {
        parts.push(render_expr(a, version));
    }
    for kw in keywords {
        match &kw.arg {
            Some(name) => parts.push(format!("{name}={}", render_expr(&kw.value, version))),
            None => parts.push(format!("**{}", render_expr(&kw.value, version))),
        }
    }
    format!("{}({})", render_expr(func, version), parts.join(", "))
}

#[must_use]
fn render_tuple(elts: &[Expr], version: &PyVersion) -> String {
    let inner: String = elts
        .iter()
        .map(|e: &Expr| render_expr(e, version))
        .collect::<Vec<String>>()
        .join(", ");
    if elts.len() == 1 {
        format!("({inner},)")
    } else {
        format!("({inner})")
    }
}

#[must_use]
fn render_dict(keys: &[Option<Expr>], values: &[Expr], version: &PyVersion) -> String {
    let pairs: Vec<String> = keys
        .iter()
        .zip(values.iter())
        .map(|(k, v): (&Option<Expr>, &Expr)| {
            k.as_ref().map_or_else(
                || format!("**{}", render_expr(v, version)),
                |key: &Expr| format!("{}: {}", render_expr(key, version), render_expr(v, version)),
            )
        })
        .collect::<Vec<String>>();
    format!("{{{}}}", pairs.join(", "))
}

#[must_use]
fn render_slice(
    lower: Option<&Expr>,
    upper: Option<&Expr>,
    step: Option<&Expr>,
    version: &PyVersion,
) -> String {
    let lo: String = lower.map_or(String::new(), |e: &Expr| render_expr(e, version));
    let hi: String = upper.map_or(String::new(), |e: &Expr| render_expr(e, version));
    match step {
        Some(s) if is_none_constant(s) => format!("{lo}:{hi}:"),
        Some(s) => format!("{lo}:{hi}:{}", render_expr(s, version)),
        None => format!("{lo}:{hi}"),
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
pub const fn conversion_suffix(conv: FormatConversion) -> &'static str {
    match conv {
        FormatConversion::None => "",
        FormatConversion::Str => "!s",
        FormatConversion::Repr => "!r",
        FormatConversion::Ascii => "!a",
    }
}

#[must_use]
pub fn render_format_spec_inner(spec: &Expr, version: &PyVersion) -> String {
    match spec {
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
                        let mut inner: String = render_expr(value, version);
                        inner.push_str(conversion_suffix(*conversion));
                        if let Some(nested) = format_spec.as_deref() {
                            inner.push(':');
                            inner.push_str(&render_format_spec_inner(nested, version));
                        }
                        out.push('{');
                        out.push_str(&inner);
                        out.push('}');
                    }
                    other => out.push_str(&render_expr(other, version)),
                }
            }
            out
        }
        Expr::Constant {
            value: ConstValue::Str(s),
            ..
        } => s.clone(),
        other => render_expr(other, version),
    }
}

#[must_use]
fn render_joinedstr(values: &[Expr], version: &PyVersion) -> String {
    crate::codegen::fstring_emit::render_joinedstr_body(values, version)
}

#[must_use]
fn render_tstr(items: &[TStrItem], version: &PyVersion) -> String {
    crate::codegen::tstring_emit::render_tstr_body(items, version)
}

#[must_use]
pub fn indent_str(level: u32) -> String {
    " ".repeat((level as usize) * 4)
}

#[must_use]
pub fn render_body(body: &[crate::ast::node::Stmt], indent: u32, version: &PyVersion) -> String {
    if body.is_empty() {
        return format!("{}pass", indent_str(indent));
    }
    let mut out: String = String::new();
    for (i, s) in body.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&render_stmt(s, indent, version));
    }
    out
}

#[must_use]
pub fn render_stmt(stmt: &crate::ast::node::Stmt, indent: u32, version: &PyVersion) -> String {
    use crate::ast::node::Stmt;
    let prefix: String = indent_str(indent);
    match stmt {
        Stmt::Pass => format!("{prefix}pass"),
        Stmt::Break => format!("{prefix}break"),
        Stmt::Continue => format!("{prefix}continue"),
        Stmt::Return(opt) => opt.as_ref().map_or_else(
            || format!("{prefix}return"),
            |e: &Expr| format!("{prefix}return {}", render_expr(e, version)),
        ),
        Stmt::Expr(e) => format!("{prefix}{}", render_expr(e, version)),
        Stmt::Assign { targets, value, .. } => {
            let lhs: String = targets
                .iter()
                .map(|t: &Expr| render_expr(t, version))
                .collect::<Vec<String>>()
                .join(" = ");
            format!("{prefix}{lhs} = {}", render_expr(value, version))
        }
        Stmt::AugAssign {
            target, op, value, ..
        } => {
            format!(
                "{prefix}{} {}= {}",
                render_expr(target, version),
                render_binop(*op),
                render_expr(value, version)
            )
        }
        Stmt::Raise { exc, cause, .. } => match (exc, cause) {
            (Some(e), Some(c)) => format!(
                "{prefix}raise {} from {}",
                render_expr(e, version),
                render_expr(c, version)
            ),
            (Some(e), None) => format!("{prefix}raise {}", render_expr(e, version)),
            (None, _) => format!("{prefix}raise"),
        },
        Stmt::Global(names) => format!("{prefix}global {}", names.join(", ")),
        Stmt::Nonlocal(names) => format!("{prefix}nonlocal {}", names.join(", ")),
        other => super::modern::emit_modern_stmt(other, indent, version)
            .unwrap_or_else(|| format!("{prefix}pass")),
    }
}
