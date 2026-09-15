use std::collections::BTreeSet;
use std::fmt;

pub const MAX_MBA_DEPTH: usize = 256;

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
        let bits: u32 = self.bits();
        if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        }
    }

    #[must_use]
    pub const fn modulus(self) -> u128 {
        1u128 << self.bits()
    }

    #[must_use]
    pub const fn is_exhaustible(self) -> bool {
        self.bits() <= 16
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
pub enum BinOp {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    Shr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnOp {
    Neg,
    Not,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Const(u64),
    Var(u32),
    Unary(UnOp, Box<Self>),
    Binary(BinOp, Box<Self>, Box<Self>),
    Ite(Box<Self>, Box<Self>, Box<Self>),
    Slice(Box<Self>, u32, u32),
    Compose(Box<Self>, Box<Self>, u32),
    Mem(Box<Self>, Width),
}

#[allow(
    clippy::should_implement_trait,
    reason = "smart constructors for a bitvector expression DSL; the std operator traits would impose Output bounds that fight the builder ergonomics"
)]
impl Expr {
    #[must_use]
    pub const fn konst(value: u64) -> Self {
        Self::Const(value)
    }

    #[must_use]
    pub const fn var(index: u32) -> Self {
        Self::Var(index)
    }

    #[must_use]
    pub fn neg(inner: Self) -> Self {
        Self::Unary(UnOp::Neg, Box::new(inner))
    }

    #[must_use]
    pub fn not(inner: Self) -> Self {
        Self::Unary(UnOp::Not, Box::new(inner))
    }

    #[must_use]
    pub fn add(left: Self, right: Self) -> Self {
        Self::Binary(BinOp::Add, Box::new(left), Box::new(right))
    }

    #[must_use]
    pub fn sub(left: Self, right: Self) -> Self {
        Self::Binary(BinOp::Sub, Box::new(left), Box::new(right))
    }

    #[must_use]
    pub fn mul(left: Self, right: Self) -> Self {
        Self::Binary(BinOp::Mul, Box::new(left), Box::new(right))
    }

    #[must_use]
    pub fn and(left: Self, right: Self) -> Self {
        Self::Binary(BinOp::And, Box::new(left), Box::new(right))
    }

    #[must_use]
    pub fn or(left: Self, right: Self) -> Self {
        Self::Binary(BinOp::Or, Box::new(left), Box::new(right))
    }

    #[must_use]
    pub fn xor(left: Self, right: Self) -> Self {
        Self::Binary(BinOp::Xor, Box::new(left), Box::new(right))
    }

    #[must_use]
    pub fn shl(left: Self, right: Self) -> Self {
        Self::Binary(BinOp::Shl, Box::new(left), Box::new(right))
    }

    #[must_use]
    pub fn shr(left: Self, right: Self) -> Self {
        Self::Binary(BinOp::Shr, Box::new(left), Box::new(right))
    }

    #[must_use]
    pub fn ite(cond: Self, then: Self, otherwise: Self) -> Self {
        Self::Ite(Box::new(cond), Box::new(then), Box::new(otherwise))
    }

    #[must_use]
    pub fn slice(inner: Self, lo: u32, hi: u32) -> Self {
        Self::Slice(Box::new(inner), lo, hi)
    }

    #[must_use]
    pub fn compose(low: Self, high: Self, low_bits: u32) -> Self {
        Self::Compose(Box::new(low), Box::new(high), low_bits)
    }

    #[must_use]
    pub fn mem(addr: Self, width: Width) -> Self {
        Self::Mem(Box::new(addr), width)
    }

    pub fn eval(&self, env: &[u64], width: Width) -> u64 {
        self.eval_with_mem(env, &|_addr: u64, _w: Width| 0, width)
    }

    pub fn eval_with_mem(&self, env: &[u64], mem: &dyn Fn(u64, Width) -> u64, width: Width) -> u64 {
        let mask: u64 = width.mask();
        match self {
            Self::Const(value) => value & mask,
            Self::Var(index) => env.get(*index as usize).copied().unwrap_or(0) & mask,
            Self::Unary(op, inner) => {
                let value: u64 = inner.eval_with_mem(env, mem, width);
                let result: u64 = match op {
                    UnOp::Neg => value.wrapping_neg(),
                    UnOp::Not => !value,
                };
                result & mask
            }
            Self::Binary(op, left, right) => {
                let lhs: u64 = left.eval_with_mem(env, mem, width);
                let rhs: u64 = right.eval_with_mem(env, mem, width);
                let result: u64 = match op {
                    BinOp::Add => lhs.wrapping_add(rhs),
                    BinOp::Sub => lhs.wrapping_sub(rhs),
                    BinOp::Mul => lhs.wrapping_mul(rhs),
                    BinOp::And => lhs & rhs,
                    BinOp::Or => lhs | rhs,
                    BinOp::Xor => lhs ^ rhs,
                    BinOp::Shl => shift_left(lhs, rhs, width),
                    BinOp::Shr => shift_right(lhs, rhs, width),
                };
                result & mask
            }
            Self::Ite(cond, then, otherwise) => {
                if cond.eval_with_mem(env, mem, width) != 0 {
                    then.eval_with_mem(env, mem, width)
                } else {
                    otherwise.eval_with_mem(env, mem, width)
                }
            }
            Self::Slice(inner, lo, hi) => {
                let value: u64 = inner.eval_with_mem(env, mem, width);
                (value >> *lo) & low_mask(hi.saturating_sub(*lo))
            }
            Self::Compose(low, high, low_bits) => {
                let lo_val: u64 = low.eval_with_mem(env, mem, width) & low_mask(*low_bits);
                let hi_val: u64 = high.eval_with_mem(env, mem, width);
                let shifted: u64 = if *low_bits >= 64 {
                    0
                } else {
                    hi_val.wrapping_shl(*low_bits)
                };
                (lo_val | shifted) & mask
            }
            Self::Mem(addr, load_width) => {
                let resolved: u64 = addr.eval_with_mem(env, mem, *load_width);
                mem(resolved, *load_width) & load_width.mask() & mask
            }
        }
    }

    pub fn collect_vars(&self, into: &mut BTreeSet<u32>) {
        match self {
            Self::Const(_) => {}
            Self::Var(index) => {
                into.insert(*index);
            }
            Self::Unary(_, inner) | Self::Slice(inner, _, _) | Self::Mem(inner, _) => {
                inner.collect_vars(into);
            }
            Self::Binary(_, left, right) => {
                left.collect_vars(into);
                right.collect_vars(into);
            }
            Self::Ite(cond, then, otherwise) => {
                cond.collect_vars(into);
                then.collect_vars(into);
                otherwise.collect_vars(into);
            }
            Self::Compose(low, high, _) => {
                low.collect_vars(into);
                high.collect_vars(into);
            }
        }
    }

    #[must_use]
    pub fn vars(&self) -> BTreeSet<u32> {
        let mut set: BTreeSet<u32> = BTreeSet::new();
        self.collect_vars(&mut set);
        set
    }

    #[must_use]
    pub fn remap_vars(&self, remap: &std::collections::BTreeMap<u32, u32>) -> Self {
        match self {
            Self::Const(value) => Self::Const(*value),
            Self::Var(index) => Self::Var(remap.get(index).copied().unwrap_or(*index)),
            Self::Unary(op, inner) => Self::Unary(*op, Box::new(inner.remap_vars(remap))),
            Self::Binary(op, left, right) => Self::Binary(
                *op,
                Box::new(left.remap_vars(remap)),
                Box::new(right.remap_vars(remap)),
            ),
            Self::Ite(cond, then, otherwise) => Self::Ite(
                Box::new(cond.remap_vars(remap)),
                Box::new(then.remap_vars(remap)),
                Box::new(otherwise.remap_vars(remap)),
            ),
            Self::Slice(inner, lo, hi) => Self::Slice(Box::new(inner.remap_vars(remap)), *lo, *hi),
            Self::Compose(low, high, low_bits) => Self::Compose(
                Box::new(low.remap_vars(remap)),
                Box::new(high.remap_vars(remap)),
                *low_bits,
            ),
            Self::Mem(addr, load_width) => Self::Mem(Box::new(addr.remap_vars(remap)), *load_width),
        }
    }

    #[must_use]
    pub fn max_var(&self) -> Option<u32> {
        self.vars().iter().next_back().copied()
    }

    #[must_use]
    pub fn node_count(&self) -> usize {
        let mut count: usize = 0;
        let mut stack: Vec<&Self> = vec![self];
        while let Some(node) = stack.pop() {
            count += 1;
            match node {
                Self::Const(_) | Self::Var(_) => {}
                Self::Unary(_, inner) | Self::Slice(inner, _, _) | Self::Mem(inner, _) => {
                    stack.push(inner);
                }
                Self::Binary(_, left, right) => {
                    stack.push(left);
                    stack.push(right);
                }
                Self::Ite(cond, then, otherwise) => {
                    stack.push(cond);
                    stack.push(then);
                    stack.push(otherwise);
                }
                Self::Compose(low, high, _) => {
                    stack.push(low);
                    stack.push(high);
                }
            }
        }
        count
    }

    #[must_use]
    pub fn depth(&self) -> usize {
        let mut max_depth: usize = 0;
        let mut stack: Vec<(&Self, usize)> = vec![(self, 1)];
        while let Some((node, level)) = stack.pop() {
            max_depth = max_depth.max(level);
            match node {
                Self::Const(_) | Self::Var(_) => {}
                Self::Unary(_, inner) | Self::Slice(inner, _, _) | Self::Mem(inner, _) => {
                    stack.push((inner, level + 1));
                }
                Self::Binary(_, left, right) => {
                    stack.push((left, level + 1));
                    stack.push((right, level + 1));
                }
                Self::Ite(cond, then, otherwise) => {
                    stack.push((cond, level + 1));
                    stack.push((then, level + 1));
                    stack.push((otherwise, level + 1));
                }
                Self::Compose(low, high, _) => {
                    stack.push((low, level + 1));
                    stack.push((high, level + 1));
                }
            }
        }
        max_depth
    }

    #[must_use]
    pub fn is_linear_mba(&self) -> bool {
        is_linear_mba_inner(self, false)
    }

    #[must_use]
    pub fn eval_truth_row(&self, bits: &[u8]) -> i128 {
        match self {
            Self::Const(value) => i128::from(*value),
            Self::Var(index) => i128::from(bits.get(*index as usize).copied().unwrap_or(0)),
            Self::Unary(op, inner) => {
                let value: i128 = inner.eval_truth_row(bits);
                match op {
                    UnOp::Neg => -value,
                    UnOp::Not => 1 - value,
                }
            }
            Self::Binary(op, left, right) => {
                if matches!(op, BinOp::Shl)
                    && let Self::Const(amount) = &**right
                {
                    let lhs: i128 = left.eval_truth_row(bits);
                    return lhs << (*amount).min(126);
                }
                let lhs: i128 = left.eval_truth_row(bits);
                let rhs: i128 = right.eval_truth_row(bits);
                match op {
                    BinOp::Add => lhs + rhs,
                    BinOp::Sub => lhs - rhs,
                    BinOp::Mul => lhs * rhs,
                    BinOp::And => i128::from((lhs != 0) && (rhs != 0)),
                    BinOp::Or => i128::from((lhs != 0) || (rhs != 0)),
                    BinOp::Xor => i128::from((lhs != 0) ^ (rhs != 0)),
                    BinOp::Shl | BinOp::Shr => 0,
                }
            }
            Self::Ite(_, _, _)
            | Self::Slice(_, _, _)
            | Self::Compose(_, _, _)
            | Self::Mem(_, _) => 0,
        }
    }
}

const fn low_mask(bits: u32) -> u64 {
    if bits == 0 {
        0
    } else if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

pub(crate) fn shift_left(value: u64, amount: u64, width: Width) -> u64 {
    let bits: u64 = u64::from(width.bits());
    if amount >= bits {
        0
    } else {
        value.wrapping_shl(amount as u32)
    }
}

pub(crate) fn shift_right(value: u64, amount: u64, width: Width) -> u64 {
    let bits: u64 = u64::from(width.bits());
    let masked: u64 = value & width.mask();
    if amount >= bits {
        0
    } else {
        masked.wrapping_shr(amount as u32)
    }
}

const fn is_all_ones_mask(value: u64) -> bool {
    matches!(value, 0xFF | 0xFFFF | 0xFFFF_FFFF | 0xFFFF_FFFF_FFFF_FFFF)
}

fn is_linear_mba_inner(expr: &Expr, inside_bitwise: bool) -> bool {
    match expr {
        Expr::Const(value) => !inside_bitwise || *value == 0 || is_all_ones_mask(*value),
        Expr::Var(_) => true,
        Expr::Unary(UnOp::Not, inner) => is_linear_mba_inner(inner, true),
        Expr::Unary(UnOp::Neg, inner) => !inside_bitwise && is_linear_mba_inner(inner, false),
        Expr::Binary(op, left, right) => match op {
            BinOp::And | BinOp::Or | BinOp::Xor => {
                is_linear_mba_inner(left, true) && is_linear_mba_inner(right, true)
            }
            BinOp::Add | BinOp::Sub => {
                !inside_bitwise
                    && is_linear_mba_inner(left, false)
                    && is_linear_mba_inner(right, false)
            }
            BinOp::Mul => !inside_bitwise && is_scaled_term(left, right),
            BinOp::Shl => {
                !inside_bitwise
                    && matches!(&**right, Expr::Const(_))
                    && is_linear_mba_inner(left, true)
            }
            BinOp::Shr => false,
        },
        Expr::Ite(_, _, _) | Expr::Slice(_, _, _) | Expr::Compose(_, _, _) | Expr::Mem(_, _) => {
            false
        }
    }
}

fn is_scaled_term(left: &Expr, right: &Expr) -> bool {
    match (left, right) {
        (Expr::Const(_), other) | (other, Expr::Const(_)) => is_linear_mba_inner(other, true),
        _ => false,
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(value) => write!(f, "{value}"),
            Self::Var(index) => write!(f, "v{index}"),
            Self::Unary(op, inner) => {
                let symbol: char = match op {
                    UnOp::Neg => '-',
                    UnOp::Not => '~',
                };
                write!(f, "{symbol}({inner})")
            }
            Self::Binary(op, left, right) => {
                let symbol: &str = match op {
                    BinOp::Add => "+",
                    BinOp::Sub => "-",
                    BinOp::Mul => "*",
                    BinOp::And => "&",
                    BinOp::Or => "|",
                    BinOp::Xor => "^",
                    BinOp::Shl => "<<",
                    BinOp::Shr => ">>",
                };
                write!(f, "({left} {symbol} {right})")
            }
            Self::Ite(cond, then, otherwise) => {
                write!(f, "ite({cond}, {then}, {otherwise})")
            }
            Self::Slice(inner, lo, hi) => write!(f, "{inner}[{lo}:{hi}]"),
            Self::Compose(low, high, low_bits) => {
                write!(f, "compose({low}, {high}, {low_bits})")
            }
            Self::Mem(addr, width) => write!(f, "mem[{addr}]:w{}", width.bits()),
        }
    }
}

pub(crate) const MAX_EXHAUSTIVE_EVALS: u128 = 1 << 24;

#[must_use]
pub fn equivalent_exhaustive(lhs: &Expr, rhs: &Expr, width: Width, var_count: u32) -> bool {
    if lhs.depth() > MAX_MBA_DEPTH || rhs.depth() > MAX_MBA_DEPTH {
        return false;
    }
    if !width.is_exhaustible() {
        return false;
    }
    let domain: u128 = if width.bits() >= 64 {
        1u128 << 64
    } else {
        u128::from(width.mask().wrapping_add(1))
    };
    let total: u128 = checked_pow(domain, var_count);
    if total > MAX_EXHAUSTIVE_EVALS {
        return false;
    }
    let mut env: Vec<u64> = vec![0; var_count as usize];
    for index in 0..total {
        decode_assignment(index, width, &mut env);
        if lhs.eval(&env, width) != rhs.eval(&env, width) {
            return false;
        }
    }
    true
}

#[must_use]
pub fn equivalent_exhaustive_runnable(width: Width, var_count: u32) -> bool {
    if !width.is_exhaustible() {
        return false;
    }
    let domain: u128 = if width.bits() >= 64 {
        1u128 << 64
    } else {
        u128::from(width.mask().wrapping_add(1))
    };
    checked_pow(domain, var_count) <= MAX_EXHAUSTIVE_EVALS
}

fn checked_pow(base: u128, exp: u32) -> u128 {
    let mut acc: u128 = 1;
    for _ in 0..exp {
        acc = acc.saturating_mul(base);
    }
    acc
}

fn decode_assignment(mut index: u128, width: Width, env: &mut [u64]) {
    let modulus: u128 = width.modulus();
    for slot in env.iter_mut() {
        *slot = (index % modulus) as u64;
        index /= modulus;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn eval_wrapping_add_masks_to_width() {
        let expr: Expr = Expr::add(Expr::konst(200), Expr::konst(100));
        assert_eq!(expr.eval(&[], Width::W8), 44);
        assert_eq!(expr.eval(&[], Width::W16), 300);
    }

    #[test]
    fn eval_not_is_width_relative() {
        let expr: Expr = Expr::not(Expr::var(0));
        assert_eq!(expr.eval(&[0], Width::W8), 0xFF);
        assert_eq!(expr.eval(&[0], Width::W4), 0x0F);
    }

    #[test]
    fn shift_beyond_width_is_zero() {
        let expr: Expr = Expr::shl(Expr::konst(1), Expr::konst(40));
        assert_eq!(expr.eval(&[], Width::W32), 0);
    }

    #[test]
    fn equivalent_detects_identity() {
        let lhs: Expr = Expr::add(Expr::var(0), Expr::var(1));
        let rhs: Expr = Expr::add(Expr::var(1), Expr::var(0));
        assert!(equivalent_exhaustive(&lhs, &rhs, Width::W4, 2));
    }

    #[test]
    fn equivalent_rejects_difference() {
        let lhs: Expr = Expr::add(Expr::var(0), Expr::var(1));
        let rhs: Expr = Expr::sub(Expr::var(0), Expr::var(1));
        assert!(!equivalent_exhaustive(&lhs, &rhs, Width::W4, 2));
    }

    #[test]
    fn ite_selects_by_condition_truth() {
        let expr: Expr = Expr::ite(Expr::var(0), Expr::var(1), Expr::var(2));
        for width in [Width::W4, Width::W8] {
            for cond in 0..=width.mask() {
                let a: u64 = 7 & width.mask();
                let b: u64 = 3 & width.mask();
                let got: u64 = expr.eval(&[cond, a, b], width);
                let expected: u64 = if cond != 0 { a } else { b };
                assert_eq!(got, expected, "ite cond={cond} at {width:?}");
            }
        }
    }

    #[test]
    fn ite_const_conditions_fold_to_branches() {
        let then: Expr = Expr::var(0);
        let otherwise: Expr = Expr::var(1);
        let pick_then: Expr = Expr::ite(Expr::konst(1), then.clone(), otherwise.clone());
        let pick_else: Expr = Expr::ite(Expr::konst(0), then.clone(), otherwise.clone());
        assert!(equivalent_exhaustive(&pick_then, &then, Width::W8, 2));
        assert!(equivalent_exhaustive(&pick_else, &otherwise, Width::W8, 2));
    }

    #[test]
    fn slice_extracts_bit_range() {
        let expr: Expr = Expr::slice(Expr::var(0), 4, 8);
        for value in 0u64..256 {
            let got: u64 = expr.eval(&[value], Width::W8);
            let expected: u64 = (value >> 4) & 0x0F;
            assert_eq!(got, expected, "slice value={value}");
        }
    }

    #[test]
    fn compose_concats_low_and_high() {
        let expr: Expr = Expr::compose(Expr::var(0), Expr::var(1), 4);
        for low in 0u64..16 {
            for high in 0u64..16 {
                let got: u64 = expr.eval(&[low, high], Width::W8);
                let expected: u64 = (low & 0x0F) | (high << 4);
                assert_eq!(got, expected & 0xFF, "compose low={low} high={high}");
            }
        }
    }

    #[test]
    fn compose_of_slices_reassembles_value() {
        let split: Expr = Expr::compose(
            Expr::slice(Expr::var(0), 0, 4),
            Expr::slice(Expr::var(0), 4, 8),
            4,
        );
        assert!(equivalent_exhaustive(&split, &Expr::var(0), Width::W8, 1));
    }

    #[test]
    fn new_nodes_are_non_linear() {
        assert!(!Expr::ite(Expr::var(0), Expr::var(1), Expr::var(2)).is_linear_mba());
        assert!(!Expr::slice(Expr::var(0), 0, 4).is_linear_mba());
        assert!(!Expr::compose(Expr::var(0), Expr::var(1), 4).is_linear_mba());
    }

    #[test]
    fn mem_eval_default_is_zero_without_store() {
        let read: Expr = Expr::mem(Expr::var(0), Width::W32);
        assert_eq!(read.eval(&[0x1000], Width::W32), 0);
    }

    #[test]
    fn mem_eval_with_mem_resolves_address_and_width() {
        let read: Expr = Expr::mem(Expr::add(Expr::var(0), Expr::konst(4)), Width::W32);
        let backing = |addr: u64, w: Width| -> u64 {
            assert_eq!(w, Width::W32);
            addr.wrapping_mul(3)
        };
        let got: u64 = read.eval_with_mem(&[0x1000], &backing, Width::W32);
        assert_eq!(got, 0x1004u64.wrapping_mul(3));
    }

    #[test]
    fn mem_load_is_masked_to_load_width() {
        let read: Expr = Expr::mem(Expr::var(0), Width::W8);
        let backing = |_addr: u64, _w: Width| -> u64 { 0xDEAD_BEEF };
        assert_eq!(read.eval_with_mem(&[0], &backing, Width::W32), 0xEF);
    }

    #[test]
    fn mem_metadata_recurses_into_address() {
        let read: Expr = Expr::mem(Expr::add(Expr::var(2), Expr::var(5)), Width::W64);
        assert_eq!(read.vars(), BTreeSet::from([2, 5]));
        assert!(!read.is_linear_mba());
        assert_eq!(read.eval_truth_row(&[0, 0, 1, 0, 0, 1]), 0);
        assert!(read.depth() >= 3);
        assert_eq!(format!("{read}"), "mem[(v2 + v5)]:w64");
    }

    #[test]
    fn linear_mba_classifier() {
        let xor_plus_carry: Expr = Expr::add(
            Expr::xor(Expr::var(0), Expr::var(1)),
            Expr::mul(Expr::konst(2), Expr::and(Expr::var(0), Expr::var(1))),
        );
        assert!(xor_plus_carry.is_linear_mba());
        let nonlinear: Expr = Expr::mul(Expr::var(0), Expr::var(1));
        assert!(!nonlinear.is_linear_mba());
    }
}
