use std::cell::Cell;

use base64::Engine as _;
use ruff_python_ast::visitor::transformer::{Transformer, walk_expr};
use ruff_python_ast::{
    AtomicNodeIndex, BoolOp, BytesLiteral, BytesLiteralFlags, BytesLiteralValue, CmpOp, Expr,
    ExprBinOp, ExprBooleanLiteral, ExprBytesLiteral, ExprCall, ExprCompare, ExprName,
    ExprNumberLiteral, ExprStringLiteral, ExprSubscript, ExprUnaryOp, Int, Number, Operator,
    StringLiteral, StringLiteralFlags, StringLiteralValue, UnaryOp,
};
use ruff_text_size::TextRange;

const MAX_PASSES: usize = 16;

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct FoldStats {
    pub(crate) passes: usize,
    pub(crate) replacements: usize,
}

struct Folder {
    replacements: Cell<usize>,
}

impl Transformer for Folder {
    fn visit_expr(&self, expr: &mut Expr) {
        walk_expr(self, expr);
        if let Some(new_node) = try_fold_node(expr) {
            *expr = new_node;
            self.replacements.set(self.replacements.get() + 1);
        }
    }
}

pub(crate) fn fold(expr: &mut Expr) -> FoldStats {
    let mut stats: FoldStats = FoldStats::default();
    for _ in 0..MAX_PASSES {
        let folder: Folder = Folder {
            replacements: Cell::new(0),
        };
        folder.visit_expr(expr);
        let pass_replacements: usize = folder.replacements.get();
        stats.passes += 1;
        stats.replacements += pass_replacements;
        if pass_replacements == 0 {
            break;
        }
    }
    stats
}

fn try_fold_node(expr: &Expr) -> Option<Expr> {
    match expr {
        Expr::BinOp(b) => fold_binop(b),
        Expr::UnaryOp(u) => fold_unop(u),
        Expr::Call(c) => fold_call(c),
        Expr::Compare(c) => fold_compare(c),
        Expr::BoolOp(b) => fold_boolop(b),
        Expr::Subscript(s) => fold_subscript(s),
        _ => None,
    }
}

fn fold_subscript(s: &ExprSubscript) -> Option<Expr> {
    let elements: &[Expr] = match s.value.as_ref() {
        Expr::List(list) => list.elts.as_slice(),
        Expr::Tuple(tuple) => tuple.elts.as_slice(),
        _ => return None,
    };
    let Literal::Int(index): Literal = literal_value(&s.slice)? else {
        return None;
    };
    let len: i128 = i128::try_from(elements.len()).ok()?;
    let resolved: i128 = if index < 0 { index + len } else { index };
    if resolved < 0 || resolved >= len {
        return None;
    }
    let pos: usize = usize::try_from(resolved).ok()?;
    let element: &Expr = elements.get(pos)?;
    if is_pure_literal(element) {
        Some(element.clone())
    } else {
        None
    }
}

fn is_pure_literal(expr: &Expr) -> bool {
    match expr {
        Expr::NumberLiteral(_)
        | Expr::StringLiteral(_)
        | Expr::BytesLiteral(_)
        | Expr::BooleanLiteral(_)
        | Expr::NoneLiteral(_)
        | Expr::EllipsisLiteral(_) => true,
        Expr::UnaryOp(u) => is_pure_literal(&u.operand),
        Expr::Tuple(t) => t.elts.iter().all(is_pure_literal),
        Expr::List(l) => l.elts.iter().all(is_pure_literal),
        _ => false,
    }
}

fn fold_binop(b: &ExprBinOp) -> Option<Expr> {
    let lhs: Literal = literal_value(&b.left)?;
    let rhs: Literal = literal_value(&b.right)?;
    let folded: Literal = match (lhs, rhs, b.op) {
        (Literal::Int(a), Literal::Int(c), Operator::Add) => Literal::Int(a.checked_add(c)?),
        (Literal::Int(a), Literal::Int(c), Operator::Sub) => Literal::Int(a.checked_sub(c)?),
        (Literal::Int(a), Literal::Int(c), Operator::Mult) => Literal::Int(a.checked_mul(c)?),
        (Literal::Int(a), Literal::Int(c), Operator::FloorDiv) if c != 0 => {
            Literal::Int(a.div_euclid(c))
        }
        (Literal::Int(a), Literal::Int(c), Operator::Mod) if c != 0 => {
            Literal::Int(a.rem_euclid(c))
        }
        (Literal::Int(a), Literal::Int(c), Operator::BitAnd) => Literal::Int(a & c),
        (Literal::Int(a), Literal::Int(c), Operator::BitOr) => Literal::Int(a | c),
        (Literal::Int(a), Literal::Int(c), Operator::BitXor) => Literal::Int(a ^ c),
        (Literal::Int(a), Literal::Int(c), Operator::LShift) if (0..128).contains(&c) => {
            Literal::Int(a.checked_shl(u32::try_from(c).ok()?)?)
        }
        (Literal::Int(a), Literal::Int(c), Operator::RShift) if (0..128).contains(&c) => {
            Literal::Int(a.checked_shr(u32::try_from(c).ok()?)?)
        }
        (Literal::Str(s), Literal::Str(t), Operator::Add) => Literal::Str(format!("{s}{t}")),
        (Literal::Str(s), Literal::Int(n), Operator::Mult) if (0..=4096).contains(&n) => {
            Literal::Str(s.repeat(usize::try_from(n).ok()?))
        }
        (Literal::Bytes(mut a), Literal::Bytes(c), Operator::Add) => {
            a.extend_from_slice(&c);
            Literal::Bytes(a)
        }
        _ => return None,
    };
    Some(folded.into_expr(b.range))
}

fn fold_unop(u: &ExprUnaryOp) -> Option<Expr> {
    let operand: Literal = literal_value(&u.operand)?;
    let folded: Literal = match (u.op, operand) {
        (UnaryOp::USub, Literal::Int(n)) => Literal::Int(n.checked_neg()?),
        (UnaryOp::UAdd, Literal::Int(n)) => Literal::Int(n),
        (UnaryOp::Invert, Literal::Int(n)) => Literal::Int(!n),
        (UnaryOp::Not, Literal::Bool(b)) => Literal::Bool(!b),
        _ => return None,
    };
    Some(folded.into_expr(u.range))
}

fn fold_call(c: &ExprCall) -> Option<Expr> {
    let Expr::Name(ExprName { id, .. }) = &*c.func else {
        return fold_method_call(c);
    };
    if !c.arguments.keywords.is_empty() || c.arguments.args.len() != 1 {
        return None;
    }
    let arg: Literal = literal_value(c.arguments.args.first()?)?;
    let folded: Literal = match (id.as_str(), arg) {
        ("chr", Literal::Int(n)) if (0..0x0011_0000).contains(&n) => {
            let ch: char = char::from_u32(u32::try_from(n).ok()?)?;
            Literal::Str(ch.to_string())
        }
        ("ord", Literal::Str(s)) if s.chars().count() == 1 => {
            Literal::Int(i128::from(s.chars().next()? as u32))
        }
        ("int", Literal::Str(s)) => Literal::Int(s.trim().parse::<i128>().ok()?),
        ("int", Literal::Int(n)) => Literal::Int(n),
        ("str", Literal::Int(n)) => Literal::Str(n.to_string()),
        ("len", Literal::Str(s)) => Literal::Int(i128::try_from(s.chars().count()).ok()?),
        ("len", Literal::Bytes(b)) => Literal::Int(i128::try_from(b.len()).ok()?),
        ("bool", Literal::Int(n)) => Literal::Bool(n != 0),
        ("bool", Literal::Bool(b)) => Literal::Bool(b),
        ("bool", Literal::Str(s)) => Literal::Bool(!s.is_empty()),
        _ => return None,
    };
    Some(folded.into_expr(c.range))
}

fn fold_method_call(c: &ExprCall) -> Option<Expr> {
    let Expr::Attribute(attr) = &*c.func else {
        return None;
    };
    if let Some(folded) = fold_int_from_bytes(c, attr) {
        return Some(folded);
    }
    if !c.arguments.keywords.is_empty() || c.arguments.args.len() != 1 {
        return None;
    }
    let arg: Literal = literal_value(c.arguments.args.first()?)?;
    match (&*attr.value, attr.attr.as_str(), arg) {
        (Expr::Name(n), "fromhex", Literal::Str(hex)) if n.id.as_str() == "bytes" => {
            let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes: Vec<u8> = (0..cleaned.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(cleaned.get(i..i + 2)?, 16).ok())
                .collect::<Option<Vec<u8>>>()?;
            Some(Literal::Bytes(bytes).into_expr(c.range))
        }
        (Expr::Name(n), "b64decode", Literal::Str(b64)) if n.id.as_str() == "base64" => {
            base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .ok()
                .map(|b| Literal::Bytes(b).into_expr(c.range))
        }
        _ => None,
    }
}

fn fold_int_from_bytes(c: &ExprCall, attr: &ruff_python_ast::ExprAttribute) -> Option<Expr> {
    if attr.attr.as_str() != "from_bytes" {
        return None;
    }
    let Expr::Name(receiver) = &*attr.value else {
        return None;
    };
    if receiver.id.as_str() != "int" {
        return None;
    }
    let [bytes_arg, order_arg]: &[Expr] = c.arguments.args.as_ref() else {
        return None;
    };
    let Literal::Bytes(bytes) = literal_value(bytes_arg)? else {
        return None;
    };
    let Literal::Str(order) = literal_value(order_arg)? else {
        return None;
    };
    let mut signed: bool = false;
    for kw in &c.arguments.keywords {
        match kw.arg.as_ref().map(ruff_python_ast::Identifier::as_str) {
            Some("signed") => {
                let Expr::BooleanLiteral(b) = &kw.value else {
                    return None;
                };
                signed = b.value;
            }
            _ => return None,
        }
    }
    if bytes.len() > 15 {
        return None;
    }
    let big_endian: bool = match order.as_str() {
        "big" => true,
        "little" => false,
        _ => return None,
    };
    let mut value: i128 = 0;
    let ordered: Vec<u8> = if big_endian {
        bytes
    } else {
        bytes.iter().rev().copied().collect()
    };
    for &byte in &ordered {
        value = (value << 8) | i128::from(byte);
    }
    if signed
        && let Some(&first) = ordered.first()
        && first & 0x80 != 0
    {
        value -= 1i128 << (8 * ordered.len());
    }
    Some(Literal::Int(value).into_expr(c.range))
}

fn fold_compare(c: &ExprCompare) -> Option<Expr> {
    if c.ops.len() != 1 || c.comparators.len() != 1 {
        return None;
    }
    let lhs: Literal = literal_value(&c.left)?;
    let rhs: Literal = literal_value(c.comparators.first()?)?;
    let op: &CmpOp = c.ops.first()?;
    let result: bool = match (lhs, rhs, op) {
        (Literal::Int(a), Literal::Int(b), CmpOp::Eq) => a == b,
        (Literal::Int(a), Literal::Int(b), CmpOp::NotEq) => a != b,
        (Literal::Int(a), Literal::Int(b), CmpOp::Lt) => a < b,
        (Literal::Int(a), Literal::Int(b), CmpOp::LtE) => a <= b,
        (Literal::Int(a), Literal::Int(b), CmpOp::Gt) => a > b,
        (Literal::Int(a), Literal::Int(b), CmpOp::GtE) => a >= b,
        (Literal::Str(a), Literal::Str(b), CmpOp::Eq) => a == b,
        (Literal::Str(a), Literal::Str(b), CmpOp::NotEq) => a != b,
        (Literal::Bool(a), Literal::Bool(b), CmpOp::Eq) => a == b,
        (Literal::Bool(a), Literal::Bool(b), CmpOp::NotEq) => a != b,
        _ => return None,
    };
    Some(Literal::Bool(result).into_expr(c.range))
}

fn fold_boolop(b: &ruff_python_ast::ExprBoolOp) -> Option<Expr> {
    let mut values: Vec<bool> = Vec::with_capacity(b.values.len());
    for v in &b.values {
        let Some(Literal::Bool(x)) = literal_value(v) else {
            return None;
        };
        values.push(x);
    }
    let result: bool = match b.op {
        BoolOp::And => values.into_iter().all(|x| x),
        BoolOp::Or => values.into_iter().any(|x| x),
    };
    Some(Literal::Bool(result).into_expr(b.range))
}

#[derive(Debug, Clone)]
enum Literal {
    Int(i128),
    Str(String),
    Bytes(Vec<u8>),
    Bool(bool),
}

impl Literal {
    fn into_expr(self, range: TextRange) -> Expr {
        match self {
            Self::Int(n) => {
                let abs: u128 = n.unsigned_abs();
                let Ok(abs_u64): core::result::Result<u64, _> = u64::try_from(abs) else {
                    return Expr::NumberLiteral(ExprNumberLiteral {
                        range,
                        node_index: AtomicNodeIndex::default(),
                        value: Number::Int(Int::from(0u64)),
                    });
                };
                let int_expr: Expr = Expr::NumberLiteral(ExprNumberLiteral {
                    range,
                    node_index: AtomicNodeIndex::default(),
                    value: Number::Int(Int::from(abs_u64)),
                });
                if n >= 0 {
                    int_expr
                } else {
                    Expr::UnaryOp(ruff_python_ast::ExprUnaryOp {
                        range,
                        node_index: AtomicNodeIndex::default(),
                        op: ruff_python_ast::UnaryOp::USub,
                        operand: Box::new(int_expr),
                    })
                }
            }
            Self::Str(s) => Expr::StringLiteral(ExprStringLiteral {
                range,
                node_index: AtomicNodeIndex::default(),
                value: StringLiteralValue::single(StringLiteral {
                    range,
                    node_index: AtomicNodeIndex::default(),
                    value: s.into_boxed_str(),
                    flags: StringLiteralFlags::empty(),
                }),
            }),
            Self::Bytes(b) => Expr::BytesLiteral(ExprBytesLiteral {
                range,
                node_index: AtomicNodeIndex::default(),
                value: BytesLiteralValue::single(BytesLiteral {
                    range,
                    node_index: AtomicNodeIndex::default(),
                    value: b.into_boxed_slice(),
                    flags: BytesLiteralFlags::empty(),
                }),
            }),
            Self::Bool(v) => Expr::BooleanLiteral(ExprBooleanLiteral {
                range,
                node_index: AtomicNodeIndex::default(),
                value: v,
            }),
        }
    }
}

fn literal_value(expr: &Expr) -> Option<Literal> {
    match expr {
        Expr::NumberLiteral(ExprNumberLiteral {
            value: Number::Int(int),
            ..
        }) => {
            let s: String = int.to_string();
            s.parse::<i128>().ok().map(Literal::Int)
        }
        Expr::StringLiteral(ExprStringLiteral { value, .. }) => {
            Some(Literal::Str(value.to_str().to_owned()))
        }
        Expr::BytesLiteral(ExprBytesLiteral { value, .. }) => Some(Literal::Bytes(
            value.iter().flat_map(|b| b.value.iter().copied()).collect(),
        )),
        Expr::BooleanLiteral(ExprBooleanLiteral { value, .. }) => Some(Literal::Bool(*value)),
        Expr::UnaryOp(ExprUnaryOp { op, operand, .. }) => match (op, literal_value(operand)?) {
            (UnaryOp::USub, Literal::Int(n)) => Some(Literal::Int(n.checked_neg()?)),
            (UnaryOp::UAdd, Literal::Int(n)) => Some(Literal::Int(n)),
            (UnaryOp::Invert, Literal::Int(n)) => Some(Literal::Int(!n)),
            (UnaryOp::Not, Literal::Bool(b)) => Some(Literal::Bool(!b)),
            _ => None,
        },
        _ => None,
    }
}
