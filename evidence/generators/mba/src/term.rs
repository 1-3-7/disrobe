use std::collections::BTreeSet;
use std::fmt::{self, Write as _};

pub const MAX_TERM_NODES: usize = 65_536;
pub const MAX_TERM_DEPTH: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Width {
    W1,
    W2,
    W4,
    W8,
    W16,
    W32,
    W64,
}

impl Width {
    pub const ALL: [Self; 7] = [
        Self::W1,
        Self::W2,
        Self::W4,
        Self::W8,
        Self::W16,
        Self::W32,
        Self::W64,
    ];

    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::W1 => 1,
            Self::W2 => 2,
            Self::W4 => 4,
            Self::W8 => 8,
            Self::W16 => 16,
            Self::W32 => 32,
            Self::W64 => 64,
        }
    }

    #[must_use]
    pub const fn mask(self) -> u64 {
        match self {
            Self::W64 => u64::MAX,
            other => (1u64 << other.bits()) - 1,
        }
    }

    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            1 => Some(Self::W1),
            2 => Some(Self::W2),
            4 => Some(Self::W4),
            8 => Some(Self::W8),
            16 => Some(Self::W16),
            32 => Some(Self::W32),
            64 => Some(Self::W64),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    Shr,
}

impl Op {
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Mul => "mul",
            Self::And => "and",
            Self::Or => "or",
            Self::Xor => "xor",
            Self::Shl => "shl",
            Self::Shr => "shr",
        }
    }

    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::And => "&",
            Self::Or => "|",
            Self::Xor => "^",
            Self::Shl => "<<",
            Self::Shr => ">>",
        }
    }

    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "add" => Some(Self::Add),
            "sub" => Some(Self::Sub),
            "mul" => Some(Self::Mul),
            "and" => Some(Self::And),
            "or" => Some(Self::Or),
            "xor" => Some(Self::Xor),
            "shl" => Some(Self::Shl),
            "shr" => Some(Self::Shr),
            _ => None,
        }
    }

    const fn apply(self, lhs: u64, rhs: u64, width: Width) -> u64 {
        match self {
            Self::Add => lhs.wrapping_add(rhs),
            Self::Sub => lhs.wrapping_sub(rhs),
            Self::Mul => lhs.wrapping_mul(rhs),
            Self::And => lhs & rhs,
            Self::Or => lhs | rhs,
            Self::Xor => lhs ^ rhs,
            Self::Shl => shift_left(lhs, rhs, width),
            Self::Shr => shift_right(lhs, rhs, width),
        }
    }
}

const fn shift_left(value: u64, amount: u64, width: Width) -> u64 {
    if amount >= width.bits() as u64 {
        0
    } else {
        value.wrapping_shl(amount as u32)
    }
}

const fn shift_right(value: u64, amount: u64, width: Width) -> u64 {
    if amount >= width.bits() as u64 {
        0
    } else {
        (value & width.mask()).wrapping_shr(amount as u32)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Term {
    Const(u64),
    Var(u32),
    Neg(Box<Self>),
    Not(Box<Self>),
    Bin(Op, Box<Self>, Box<Self>),
}

#[allow(
    clippy::should_implement_trait,
    reason = "smart constructors for a bitvector expression model; the std operator traits would impose Output bounds that fight the builder ergonomics"
)]
impl Term {
    #[must_use]
    pub const fn constant(value: u64) -> Self {
        Self::Const(value)
    }

    #[must_use]
    pub const fn var(index: u32) -> Self {
        Self::Var(index)
    }

    #[must_use]
    pub fn neg(inner: Self) -> Self {
        Self::Neg(Box::new(inner))
    }

    #[must_use]
    pub fn not(inner: Self) -> Self {
        Self::Not(Box::new(inner))
    }

    #[must_use]
    pub fn bin(op: Op, left: Self, right: Self) -> Self {
        Self::Bin(op, Box::new(left), Box::new(right))
    }

    #[must_use]
    pub fn add(left: Self, right: Self) -> Self {
        Self::bin(Op::Add, left, right)
    }

    #[must_use]
    pub fn sub(left: Self, right: Self) -> Self {
        Self::bin(Op::Sub, left, right)
    }

    #[must_use]
    pub fn mul(left: Self, right: Self) -> Self {
        Self::bin(Op::Mul, left, right)
    }

    #[must_use]
    pub fn and(left: Self, right: Self) -> Self {
        Self::bin(Op::And, left, right)
    }

    #[must_use]
    pub fn or(left: Self, right: Self) -> Self {
        Self::bin(Op::Or, left, right)
    }

    #[must_use]
    pub fn xor(left: Self, right: Self) -> Self {
        Self::bin(Op::Xor, left, right)
    }

    #[must_use]
    pub fn eval(&self, env: &[u64], width: Width) -> u64 {
        let mask: u64 = width.mask();
        match self {
            Self::Const(value) => value & mask,
            Self::Var(index) => env.get(*index as usize).copied().unwrap_or(0) & mask,
            Self::Neg(inner) => inner.eval(env, width).wrapping_neg() & mask,
            Self::Not(inner) => !inner.eval(env, width) & mask,
            Self::Bin(op, left, right) => {
                let lhs: u64 = left.eval(env, width);
                let rhs: u64 = right.eval(env, width);
                op.apply(lhs, rhs, width) & mask
            }
        }
    }

    #[must_use]
    pub fn node_count(&self) -> usize {
        match self {
            Self::Const(_) | Self::Var(_) => 1,
            Self::Neg(inner) | Self::Not(inner) => 1 + inner.node_count(),
            Self::Bin(_, left, right) => 1 + left.node_count() + right.node_count(),
        }
    }

    #[must_use]
    pub fn depth(&self) -> usize {
        match self {
            Self::Const(_) | Self::Var(_) => 1,
            Self::Neg(inner) | Self::Not(inner) => 1 + inner.depth(),
            Self::Bin(_, left, right) => 1 + left.depth().max(right.depth()),
        }
    }

    pub fn collect_vars(&self, into: &mut BTreeSet<u32>) {
        match self {
            Self::Const(_) => {}
            Self::Var(index) => {
                into.insert(*index);
            }
            Self::Neg(inner) | Self::Not(inner) => inner.collect_vars(into),
            Self::Bin(_, left, right) => {
                left.collect_vars(into);
                right.collect_vars(into);
            }
        }
    }

    #[must_use]
    pub fn vars(&self) -> BTreeSet<u32> {
        let mut found: BTreeSet<u32> = BTreeSet::new();
        self.collect_vars(&mut found);
        found
    }

    #[must_use]
    pub fn var_count(&self) -> u32 {
        self.vars().last().map_or(0, |highest: &u32| highest + 1)
    }

    #[must_use]
    pub fn subterm(&self, index: usize) -> Option<&Self> {
        let mut cursor: usize = 0;
        self.subterm_walk(index, &mut cursor)
    }

    fn subterm_walk(&self, target: usize, cursor: &mut usize) -> Option<&Self> {
        if *cursor == target {
            return Some(self);
        }
        *cursor += 1;
        match self {
            Self::Const(_) | Self::Var(_) => None,
            Self::Neg(inner) | Self::Not(inner) => inner.subterm_walk(target, cursor),
            Self::Bin(_, left, right) => left
                .subterm_walk(target, cursor)
                .or_else(|| right.subterm_walk(target, cursor)),
        }
    }

    #[must_use]
    pub fn replace_subterm(&self, index: usize, replacement: &Self) -> Option<Self> {
        let mut cursor: usize = 0;
        self.replace_walk(index, replacement, &mut cursor)
    }

    fn replace_walk(&self, target: usize, replacement: &Self, cursor: &mut usize) -> Option<Self> {
        if *cursor == target {
            return Some(replacement.clone());
        }
        *cursor += 1;
        match self {
            Self::Const(_) | Self::Var(_) => None,
            Self::Neg(inner) => inner
                .replace_walk(target, replacement, cursor)
                .map(Self::neg),
            Self::Not(inner) => inner
                .replace_walk(target, replacement, cursor)
                .map(Self::not),
            Self::Bin(op, left, right) => {
                if let Some(rebuilt) = left.replace_walk(target, replacement, cursor) {
                    return Some(Self::bin(*op, rebuilt, right.as_ref().clone()));
                }
                right
                    .replace_walk(target, replacement, cursor)
                    .map(|rebuilt: Self| Self::bin(*op, left.as_ref().clone(), rebuilt))
            }
        }
    }

    #[must_use]
    pub fn to_prefix(&self) -> String {
        let mut rendered: String = String::new();
        self.write_prefix(&mut rendered);
        rendered
    }

    fn write_prefix(&self, into: &mut String) {
        match self {
            Self::Const(value) => {
                let _ = write!(into, "(const {value})");
            }
            Self::Var(index) => {
                let _ = write!(into, "(var {index})");
            }
            Self::Neg(inner) => {
                into.push_str("(neg ");
                inner.write_prefix(into);
                into.push(')');
            }
            Self::Not(inner) => {
                into.push_str("(not ");
                inner.write_prefix(into);
                into.push(')');
            }
            Self::Bin(op, left, right) => {
                into.push('(');
                into.push_str(op.tag());
                into.push(' ');
                left.write_prefix(into);
                into.push(' ');
                right.write_prefix(into);
                into.push(')');
            }
        }
    }
}

impl fmt::Display for Term {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(value) => write!(formatter, "{value}"),
            Self::Var(index) => write!(formatter, "v{index}"),
            Self::Neg(inner) => write!(formatter, "(-{inner})"),
            Self::Not(inner) => write!(formatter, "(~{inner})"),
            Self::Bin(op, left, right) => {
                write!(formatter, "({left} {} {right})", op.symbol())
            }
        }
    }
}
