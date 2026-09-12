use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::expr::{BinOp, Expr, UnOp, Width};
use crate::opaque::{CmpOp, Predicate};

#[derive(Debug)]
struct Lowering {
    width: Width,
    vars: BTreeSet<u32>,
    mem: BTreeMap<String, String>,
}

impl Lowering {
    const fn new(width: Width) -> Self {
        Self {
            width,
            vars: BTreeSet::new(),
            mem: BTreeMap::new(),
        }
    }

    const fn bits(&self) -> u32 {
        self.width.bits()
    }

    fn zero(&self) -> String {
        format!("(_ bv0 {})", self.bits())
    }

    fn konst(&self, value: u64) -> String {
        let masked: u64 = value & self.width.mask();
        format!("(_ bv{masked} {})", self.bits())
    }

    fn mem_name(&mut self, key: String) -> String {
        if let Some(existing) = self.mem.get(&key) {
            return existing.clone();
        }
        let name: String = format!("mem_{}", self.mem.len());
        self.mem.insert(key, name.clone());
        name
    }

    fn zero_extend(&self, term: String, from_width: u32) -> String {
        let bits: u32 = self.bits();
        if from_width >= bits {
            return term;
        }
        let pad: u32 = bits - from_width;
        format!("((_ zero_extend {pad}) {term})")
    }

    fn mask_low(&self, term: String, keep_bits: u32) -> String {
        let bits: u32 = self.bits();
        if keep_bits >= bits {
            return term;
        }
        let mask_value: u64 = (1u64 << keep_bits) - 1;
        format!("(bvand {term} (_ bv{mask_value} {bits}))")
    }

    fn shift_left_const(&self, term: String, amount: u32) -> String {
        let bits: u32 = self.bits();
        if amount >= bits {
            return self.zero();
        }
        format!("(bvshl {term} (_ bv{amount} {bits}))")
    }

    fn lower_slice(&mut self, inner: &Expr, lo: u32, hi: u32) -> String {
        let inner_term: String = self.lower_expr(inner);
        if hi <= lo {
            return self.zero();
        }
        let bits: u32 = self.bits();
        let high_bit: u32 = (hi - 1).min(bits.saturating_sub(1));
        let low_bit: u32 = lo.min(high_bit);
        let extracted_width: u32 = high_bit - low_bit + 1;
        let extracted: String = format!("((_ extract {high_bit} {low_bit}) {inner_term})");
        self.zero_extend(extracted, extracted_width)
    }

    fn lower_compose(&mut self, low: &Expr, high: &Expr, low_bits: u32) -> String {
        let low_term: String = self.lower_expr(low);
        let high_term: String = self.lower_expr(high);
        let bits: u32 = self.bits();
        if low_bits == 0 {
            return high_term;
        }
        if low_bits >= bits {
            return low_term;
        }
        let low_masked: String = self.mask_low(low_term, low_bits);
        let high_shifted: String = self.shift_left_const(high_term, low_bits);
        format!("(bvor {low_masked} {high_shifted})")
    }

    fn lower_expr(&mut self, expr: &Expr) -> String {
        match expr {
            Expr::Const(value) => self.konst(*value),
            Expr::Var(index) => {
                self.vars.insert(*index);
                format!("v{index}")
            }
            Expr::Unary(op, inner) => {
                let inner_term: String = self.lower_expr(inner);
                let name: &str = match op {
                    UnOp::Neg => "bvneg",
                    UnOp::Not => "bvnot",
                };
                format!("({name} {inner_term})")
            }
            Expr::Binary(op, left, right) => {
                let left_term: String = self.lower_expr(left);
                let right_term: String = self.lower_expr(right);
                let name: &str = match op {
                    BinOp::Add => "bvadd",
                    BinOp::Sub => "bvsub",
                    BinOp::Mul => "bvmul",
                    BinOp::And => "bvand",
                    BinOp::Or => "bvor",
                    BinOp::Xor => "bvxor",
                    BinOp::Shl => "bvshl",
                    BinOp::Shr => "bvlshr",
                };
                format!("({name} {left_term} {right_term})")
            }
            Expr::Ite(cond, then_branch, else_branch) => {
                let cond_term: String = self.lower_expr(cond);
                let then_term: String = self.lower_expr(then_branch);
                let else_term: String = self.lower_expr(else_branch);
                let zero: String = self.zero();
                format!("(ite (not (= {cond_term} {zero})) {then_term} {else_term})")
            }
            Expr::Slice(inner, lo, hi) => self.lower_slice(inner, *lo, *hi),
            Expr::Compose(low, high, low_bits) => self.lower_compose(low, high, *low_bits),
            Expr::Mem(addr, load_width) => {
                let key: String = format!("mem:{addr}:{}", load_width.bits());
                self.mem_name(key)
            }
        }
    }

    fn compare(op: CmpOp, left: &str, right: &str) -> String {
        match op {
            CmpOp::Eq => format!("(= {left} {right})"),
            CmpOp::Ne => format!("(not (= {left} {right}))"),
            CmpOp::UnsignedLt => format!("(bvult {left} {right})"),
            CmpOp::UnsignedLe => format!("(bvule {left} {right})"),
            CmpOp::UnsignedGt => format!("(bvult {right} {left})"),
            CmpOp::UnsignedGe => format!("(bvule {right} {left})"),
            CmpOp::SignedLt => format!("(bvslt {left} {right})"),
            CmpOp::SignedLe => format!("(bvsle {left} {right})"),
            CmpOp::SignedGt => format!("(bvslt {right} {left})"),
            CmpOp::SignedGe => format!("(bvsle {right} {left})"),
        }
    }

    fn lower_predicate(&mut self, predicate: &Predicate) -> String {
        match predicate {
            Predicate::Compare { op, left, right } => {
                let left_term: String = self.lower_expr(left);
                let right_term: String = self.lower_expr(right);
                Self::compare(*op, &left_term, &right_term)
            }
            Predicate::Nonzero(inner) => {
                let inner_term: String = self.lower_expr(inner);
                let zero: String = self.zero();
                format!("(not (= {inner_term} {zero}))")
            }
            Predicate::Or(left, right) => {
                let left_term: String = self.lower_predicate(left);
                let right_term: String = self.lower_predicate(right);
                format!("(or {left_term} {right_term})")
            }
            Predicate::And(left, right) => {
                let left_term: String = self.lower_predicate(left);
                let right_term: String = self.lower_predicate(right);
                format!("(and {left_term} {right_term})")
            }
        }
    }

    fn assemble(&self, assertion: &str) -> String {
        let bits: u32 = self.bits();
        let mut out: String = String::from("(set-logic QF_BV)\n");
        for index in &self.vars {
            let _ = writeln!(out, "(declare-fun v{index} () (_ BitVec {bits}))");
        }
        for name in self.mem.values() {
            let _ = writeln!(out, "(declare-fun {name} () (_ BitVec {bits}))");
        }
        let _ = writeln!(out, "(assert {assertion})");
        out.push_str("(check-sat)\n");
        out
    }
}

#[must_use]
pub fn equivalence_query(left: &Expr, right: &Expr, width: Width) -> String {
    let mut lowering: Lowering = Lowering::new(width);
    let left_term: String = lowering.lower_expr(left);
    let right_term: String = lowering.lower_expr(right);
    let disequality: String = format!("(not (= {left_term} {right_term}))");
    lowering.assemble(&disequality)
}

#[must_use]
pub fn tautology_refutation_query(predicate: &Predicate, width: Width) -> String {
    let mut lowering: Lowering = Lowering::new(width);
    let term: String = lowering.lower_predicate(predicate);
    let negation: String = format!("(not {term})");
    lowering.assemble(&negation)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn equivalence_query_declares_shared_vars_once_and_asserts_disequality() {
        let left: Expr = Expr::add(Expr::var(0), Expr::var(1));
        let right: Expr = Expr::add(Expr::var(1), Expr::var(0));
        let script: String = equivalence_query(&left, &right, Width::W8);
        assert!(script.contains("(set-logic QF_BV)"));
        assert!(script.contains("(declare-fun v0 () (_ BitVec 8))"));
        assert!(script.contains("(declare-fun v1 () (_ BitVec 8))"));
        assert_eq!(script.matches("(declare-fun v0").count(), 1);
        assert!(script.contains("(assert (not (= (bvadd v0 v1) (bvadd v1 v0))))"));
        assert!(script.trim_end().ends_with("(check-sat)"));
    }

    #[test]
    fn constants_are_masked_to_the_query_width() {
        let expr: Expr = Expr::konst(0x1FF);
        let script: String = equivalence_query(&expr, &Expr::konst(0xFF), Width::W8);
        assert!(script.contains("(_ bv255 8)"));
        assert!(!script.contains("511"));
    }

    #[test]
    fn shift_right_lowers_to_logical_shift() {
        let expr: Expr = Expr::shr(Expr::var(0), Expr::konst(1));
        let script: String = equivalence_query(&expr, &Expr::var(0), Width::W16);
        assert!(script.contains("(bvlshr v0 (_ bv1 16))"));
    }

    #[test]
    fn predicate_refutation_lowers_comparison_and_negates() {
        let predicate: Predicate =
            Predicate::eq(Expr::and(Expr::var(0), Expr::konst(1)), Expr::konst(0));
        let script: String = tautology_refutation_query(&predicate, Width::W8);
        assert!(script.contains("(assert (not (= (bvand v0 (_ bv1 8)) (_ bv0 8))))"));
    }
}
