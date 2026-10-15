use std::hash::{DefaultHasher, Hash, Hasher};
use std::rc::Rc;

use crate::u256::U256;

const MAX_WEIGHT: u32 = 384;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum CdLoc {
    Word0,
    Head(u16),
    Length(u16),
    Element(u16),
    Nested(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Env {
    Address,
    Origin,
    Caller,
    CallValue,
    GasPrice,
    Coinbase,
    Timestamp,
    Number,
    PrevRandao,
    GasLimit,
    ChainId,
    SelfBalance,
    BaseFee,
    BlobBaseFee,
    CodeSize,
    ReturnDataSize,
    Gas,
    MemorySize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum UnOp {
    IsZero,
    Not,
    Balance,
    ExtCodeSize,
    ExtCodeHash,
    BlockHash,
    BlobHash,
    Clz,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum BinOp {
    Add,
    Mul,
    Sub,
    Div,
    SDiv,
    Mod,
    SMod,
    Exp,
    SignExtend,
    Lt,
    Gt,
    Slt,
    Sgt,
    Eq,
    And,
    Or,
    Xor,
    Byte,
    Shl,
    Shr,
    Sar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TernOp {
    AddMod,
    MulMod,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) enum Expr {
    Const(U256),
    Cd(CdLoc),
    CdRaw(Val),
    CdSize,
    Env(Env),
    Un(UnOp, Val),
    Bin(BinOp, Val, Val),
    Tern(TernOp, Val, Val, Val),
    Sload(Val),
    Tload(Val),
    Keccak(Vec<Val>),
    CallResult(u32),
    Created(u32),
    Opaque(u32),
}

#[derive(Debug)]
pub(crate) struct Node {
    pub(crate) expr: Expr,
    pub(crate) weight: u32,
    pub(crate) hash: u64,
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.expr == other.expr
    }
}

impl Eq for Node {}

impl Hash for Node {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

pub(crate) type Val = Rc<Node>;

fn child_weight(expr: &Expr) -> u32 {
    match expr {
        Expr::Const(_)
        | Expr::Cd(_)
        | Expr::CdSize
        | Expr::Env(_)
        | Expr::CallResult(_)
        | Expr::Created(_)
        | Expr::Opaque(_) => 0,
        Expr::CdRaw(a) | Expr::Un(_, a) | Expr::Sload(a) | Expr::Tload(a) => a.weight,
        Expr::Bin(_, a, b) => a.weight.saturating_add(b.weight),
        Expr::Tern(_, a, b, c) => a.weight.saturating_add(b.weight).saturating_add(c.weight),
        Expr::Keccak(words) => words
            .iter()
            .fold(0u32, |sum: u32, word: &Val| sum.saturating_add(word.weight)),
    }
}

pub(crate) fn node(expr: Expr, pc: u32) -> Val {
    let weight: u32 = child_weight(&expr).saturating_add(1);
    if weight > MAX_WEIGHT {
        return node(Expr::Opaque(pc), pc);
    }
    let mut hasher: DefaultHasher = DefaultHasher::new();
    expr.hash(&mut hasher);
    Rc::new(Node {
        expr,
        weight,
        hash: hasher.finish(),
    })
}

pub(crate) fn konst(value: U256) -> Val {
    node(Expr::Const(value), 0)
}

pub(crate) fn as_const(value: &Val) -> Option<U256> {
    match value.expr {
        Expr::Const(constant) => Some(constant),
        _ => None,
    }
}

fn fold_bin(op: BinOp, a: U256, b: U256) -> U256 {
    match op {
        BinOp::Add => a.wrapping_add(b),
        BinOp::Mul => a.wrapping_mul(b),
        BinOp::Sub => a.wrapping_sub(b),
        BinOp::Div => a.div_rem(b).0,
        BinOp::SDiv => a.sdiv(b),
        BinOp::Mod => a.div_rem(b).1,
        BinOp::SMod => a.smod(b),
        BinOp::Exp => a.wrapping_pow(b),
        BinOp::SignExtend => b.signextend(a),
        BinOp::Lt => U256::from_bool(a < b),
        BinOp::Gt => U256::from_bool(a > b),
        BinOp::Slt => U256::from_bool(a.signed_cmp(b).is_lt()),
        BinOp::Sgt => U256::from_bool(a.signed_cmp(b).is_gt()),
        BinOp::Eq => U256::from_bool(a == b),
        BinOp::And => a & b,
        BinOp::Or => a | b,
        BinOp::Xor => a ^ b,
        BinOp::Byte => b.byte(a),
        BinOp::Shl => b.shift_left(a.shift_amount()),
        BinOp::Shr => b.shift_right(a.shift_amount()),
        BinOp::Sar => b.sar(a.shift_amount()),
    }
}

pub(crate) fn bin(op: BinOp, a: Val, b: Val, pc: u32) -> Val {
    if let (Some(x), Some(y)) = (as_const(&a), as_const(&b)) {
        return konst(fold_bin(op, x, y));
    }
    let ca: Option<U256> = as_const(&a);
    let cb: Option<U256> = as_const(&b);
    match op {
        BinOp::Add => {
            if ca.is_some_and(U256::is_zero) {
                return b;
            }
            if cb.is_some_and(U256::is_zero) {
                return a;
            }
            if let Some(constant) = ca {
                return add_const(b, constant, pc);
            }
            if let Some(constant) = cb {
                return add_const(a, constant, pc);
            }
        }
        BinOp::Sub => {
            if cb.is_some_and(U256::is_zero) {
                return a;
            }
            if a == b {
                return konst(U256::ZERO);
            }
            if let Some(constant) = cb {
                return add_const(a, constant.wrapping_neg(), pc);
            }
            if ca.is_none() {
                let left: Affine = affine(&a);
                let right: Affine = affine(&b);
                let mut left_terms: Vec<u64> = left.terms.iter().map(|t: &Val| t.hash).collect();
                let mut right_terms: Vec<u64> = right.terms.iter().map(|t: &Val| t.hash).collect();
                left_terms.sort_unstable();
                right_terms.sort_unstable();
                if left_terms == right_terms {
                    return konst(left.constant.wrapping_sub(right.constant));
                }
            }
        }
        BinOp::Mul => {
            if ca.is_some_and(U256::is_zero) || cb.is_some_and(U256::is_zero) {
                return konst(U256::ZERO);
            }
            if ca == Some(U256::ONE) {
                return b;
            }
            if cb == Some(U256::ONE) {
                return a;
            }
            if ca.is_some() {
                return node(Expr::Bin(op, b, a), pc);
            }
        }
        BinOp::Div => {
            if cb == Some(U256::ONE) {
                return a;
            }
        }
        BinOp::And => {
            if ca.is_some_and(U256::is_zero) || cb.is_some_and(U256::is_zero) {
                return konst(U256::ZERO);
            }
            if ca == Some(U256::MAX) {
                return b;
            }
            if cb == Some(U256::MAX) {
                return a;
            }
            if a == b {
                return a;
            }
            if ca.is_some() {
                return bin(op, b, a, pc);
            }
            if let (Some(outer), Expr::Bin(BinOp::And, inner, mask)) = (cb, &a.expr)
                && let Some(mask) = as_const(mask)
            {
                return bin(BinOp::And, inner.clone(), konst(outer & mask), pc);
            }
        }
        BinOp::Or | BinOp::Xor => {
            if ca.is_some_and(U256::is_zero) {
                return b;
            }
            if cb.is_some_and(U256::is_zero) {
                return a;
            }
            if op == BinOp::Xor && a == b {
                return konst(U256::ZERO);
            }
            if ca.is_some() {
                return node(Expr::Bin(op, b, a), pc);
            }
        }
        BinOp::Eq => {
            if a == b {
                return konst(U256::ONE);
            }
            if ca.is_some() {
                return node(Expr::Bin(op, b, a), pc);
            }
        }
        BinOp::Shl | BinOp::Shr | BinOp::Sar if ca.is_some_and(U256::is_zero) => {
            return b;
        }
        _ => {}
    }
    node(Expr::Bin(op, a, b), pc)
}

fn add_const(value: Val, constant: U256, pc: u32) -> Val {
    if constant.is_zero() {
        return value;
    }
    if let Expr::Bin(BinOp::Add, inner, existing) = &value.expr
        && let Some(existing) = as_const(existing)
    {
        let sum: U256 = existing.wrapping_add(constant);
        if sum.is_zero() {
            return inner.clone();
        }
        return node(Expr::Bin(BinOp::Add, inner.clone(), konst(sum)), pc);
    }
    node(Expr::Bin(BinOp::Add, value, konst(constant)), pc)
}

pub(crate) fn un(op: UnOp, a: Val, pc: u32) -> Val {
    if let Some(constant) = as_const(&a) {
        match op {
            UnOp::IsZero => return konst(U256::from_bool(constant.is_zero())),
            UnOp::Not => return konst(!constant),
            UnOp::Clz => return konst(U256::from_u64(u64::from(constant.leading_zeros()))),
            _ => {}
        }
    }
    if op == UnOp::Not
        && let Expr::Un(UnOp::Not, inner) = &a.expr
    {
        return inner.clone();
    }
    if op == UnOp::IsZero
        && let Expr::Un(UnOp::IsZero, inner) = &a.expr
        && let Expr::Un(UnOp::IsZero, innermost) = &inner.expr
    {
        return node(Expr::Un(UnOp::IsZero, innermost.clone()), pc);
    }
    node(Expr::Un(op, a), pc)
}

pub(crate) fn tern(op: TernOp, a: Val, b: Val, c: Val, pc: u32) -> Val {
    if let (Some(x), Some(y), Some(n)) = (as_const(&a), as_const(&b), as_const(&c)) {
        if n.is_zero() {
            return konst(U256::ZERO);
        }
        let exact: Option<U256> = match op {
            TernOp::AddMod => {
                let (sum, carry) = x.overflowing_add(y);
                (!carry).then(|| sum.div_rem(n).1)
            }
            TernOp::MulMod => {
                let wide: bool = x.bits() + y.bits() > 256;
                (!wide).then(|| x.wrapping_mul(y).div_rem(n).1)
            }
        };
        if let Some(value) = exact {
            return konst(value);
        }
    }
    node(Expr::Tern(op, a, b, c), pc)
}

pub(crate) struct Affine {
    pub(crate) constant: U256,
    pub(crate) terms: Vec<Val>,
}

pub(crate) fn affine(value: &Val) -> Affine {
    let mut out: Affine = Affine {
        constant: U256::ZERO,
        terms: Vec::new(),
    };
    let mut work: Vec<Val> = vec![value.clone()];
    while let Some(item) = work.pop() {
        match &item.expr {
            Expr::Const(constant) => out.constant = out.constant.wrapping_add(*constant),
            Expr::Bin(BinOp::Add, a, b) if out.terms.len() + work.len() < 16 => {
                work.push(a.clone());
                work.push(b.clone());
            }
            _ => out.terms.push(item.clone()),
        }
    }
    out
}

pub(crate) fn is_selector(value: &Val) -> bool {
    match &value.expr {
        Expr::Bin(BinOp::Shr, shift, word) => {
            as_const(shift) == Some(U256::from_u64(224))
                && matches!(word.expr, Expr::Cd(CdLoc::Word0))
        }
        Expr::Bin(BinOp::Div, word, divisor) => {
            matches!(word.expr, Expr::Cd(CdLoc::Word0))
                && as_const(divisor) == Some(U256::ONE.shift_left(224))
        }
        Expr::Bin(BinOp::And, inner, mask) => {
            as_const(mask) == Some(U256::from_u64(0xffff_ffff)) && is_selector(inner)
        }
        _ => false,
    }
}

pub(crate) fn mentions(value: &Val, predicate: &dyn Fn(&Expr) -> bool, budget: &mut u32) -> bool {
    if *budget == 0 {
        return false;
    }
    *budget -= 1;
    if predicate(&value.expr) {
        return true;
    }
    match &value.expr {
        Expr::CdRaw(a) | Expr::Un(_, a) | Expr::Sload(a) | Expr::Tload(a) => {
            mentions(a, predicate, budget)
        }
        Expr::Bin(_, a, b) => mentions(a, predicate, budget) || mentions(b, predicate, budget),
        Expr::Tern(_, a, b, c) => {
            mentions(a, predicate, budget)
                || mentions(b, predicate, budget)
                || mentions(c, predicate, budget)
        }
        Expr::Keccak(words) => words
            .iter()
            .any(|word: &Val| mentions(word, predicate, budget)),
        _ => false,
    }
}
